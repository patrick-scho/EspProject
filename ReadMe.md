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

### Sending encrypted messages



### Receiving encrypted messages

