# A C client library for Matrix.org

This is a C library implementing a small portion of the [Matrix.org](https://matrix.org) [Client-Server protocol](https://spec.matrix.org/latest/client-server-api/).
It can be used to connect to a Matrix server and send/receive (end-to-end encrypted) messages.
The implementation is largely platform independant, apart from HTTP GET/PUT/POST methods which have to be implemented for each platform.
An implementation for desktop systems based on CURL, as well as one for the ESP32 is included.

## Dependencies

The library depends on the [olm library](https://gitlab.matrix.org/matrix-org/olm/) for cryptography and [mjson](https://github.com/cesanta/mjson) for reading and writing JSON data.
If you want to use the CURL based version for desktop, you need [libcurl](https://curl.se/libcurl/).
The current `build.sh` build file expects olm and mjson to be in c/ext, and libcurl to be installed on the host system.

## Usage

The library itself is implemented in two files, `matrix.h/.c`, which can be found in c/src.
Additionally, there are several files implementing the necessary HTTP methods.
`c/src/httpStruct.h` contains the definitions that have to be implemented, and `httpCurl.h/httpEsp32.h` contain the specific implementations for those platforms.
They include all the functions used to interface with a Matrix server.
Currently the Matrix server is defined statically in `matrix.h` as `MATRIX_SERVER`.

Most functions take a `HttpCallbacks` pointer, as defined in `httpStruct.h`.
This has to be initialized prior to calling any function that sends/receives data.
When using CURL this looks like

```
#include <httpStruct.h>
#include <httpCurl.h>

...

curl_global_init(CURL_GLOBAL_DEFAULT);
CURL *curl = curl_easy_init();

HttpCallbacks http;
http.data = curl;
http.get = curlGet;
http.put = curlPut;
http.post = curlPost;
```

and for the ESP32 it looks like

```
#include <httpStruct.h>
#include <httpEsp32.h>

...

WiFiClientSecure *client = new WiFiClientSecure();

HttpCallbacks http;
http.data = client;
http.get = esp32Get;
http.put = esp32Put;
http.post = esp32Post;

...

delete client;
```

The functions themselves are documented in `matrix.h`.
Below are examples for how to send and receive encrypted messages from a room whose RoomId is known.
The usage roughly corresponds to the description in https://matrix.org/docs/guides/end-to-end-encryption-implementation-guide/.
Additionally, `c/src/main.c` can be viewed as an example of how to do most things the library supports.

### Sending encrypted messages

In order to send messages in a room configured to use encryption, proceed as follows:

- set data in matrix.h
  - uToken: user token (see login)
  - uId: user id (@<name>:<server>, e.g. @pscho:matrix.org)
  - dId: device id (see login)
  - dKey: device key (see generating olm session)
- initialize olm structs
  - `OlmAccount *olmAcc = createOlmAccount();` (or load account using `loadOlmAccount`)
  - `OlmSession *olmSess = olm_session(malloc(olm_session_size()));`
  - `OlmOutboundGroupSession *outboundGroupSess = olm_outbound_group_session(malloc olm_outbound_group_session_size()));`
- login
  - call `login` with username, password and any name for the new device
  - this returns a JSON object of the form ```
    {
        "access_token": "abc123",
        "device_id": "GHTYAJCE",
        "expires_in_ms": 60000,
        "refresh_token": "def456",
        "user_id": "@cheeky_monkey:matrix.org",
        "well_known": {
            "m.homeserver": {
            "base_url": "https://example.org"
            },
            "m.identity_server": {
            "base_url": "https://id.example.org"
            }
        }
    }```
  - access_token and device_id have to be copied into `matrix.h`
- generate outbound megolm session
  - call `initOutboundGroupSession`
  - after using this session, save to a buffer using `saveOutboundGroupSession` and load the next time
  - also save/load OlmAccount (and OlmSession)
- generate olm session from onetime key
  - select a device to send Megolm keys to. either select known device or list devices (see "list devices" in c/src/main.c)
  - claim a onetime key using `claimOnetimeKey` with the deviceId
  - get device key (see "list devices" c/src/main.c)
  - call `createOlmSession` with the onetime key
- send m.room_key
  - get megolm session key ```
        size_t keyLen = olm_outbound_group_session_key_length(outboundGroupSess);
        uint8_t *key = (uint8_t *)malloc(keyLen);
        olm_outbound_group_session_key(outboundGroupSess, key, keyLen);```
  - the next three steps can be accomplished by calling `sendRoomKeyToDevice`
  - create m.room_key using `generateRoomKeyEvent`
  - encrypt using `createEncryptedOlmEvent`
  - send to device using `sendToDevice`
- send encrypted message
  - send message using `sendGroupMsg`


### Receiving encrypted messages

TODO