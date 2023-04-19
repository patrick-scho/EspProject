#ifndef MATRIX__H
#define MATRIX__H


#include <mjson.h>
#include <olm/olm.h>

#include "httpStruct.h"


#define KEY_LEN 100 // 43
#define SIG_LEN 128 // 86
#define TMP_LEN 1024*4
#define URL_LEN 128
#define RND_LEN 1024
#define DEVICE_KEYS_BUF_LEN 1024
#define ONETIME_KEYS_BUF_LEN 1024
#define MATRIX_SERVER "https://matrix.org"

static const char *uToken = "syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A";
static const char *uId = "@pscho:matrix.org";
static const char *dId = "ZGAUCOSULH";
static const char *dKey = "5KjCB+kjNlRJhTFxxdfUcr/erraW08V0uZOEe7UYHTM";


// utility
//--------

// check a size_t result from olm functions
// and print potential error
void checkAccountError(OlmAccount *olmAcc, size_t res);

void checkSessionError(OlmSession *olmSess, size_t res);

void checkOutboundSessionError(OlmOutboundGroupSession *olmOutboundSess, size_t res);

// generate len random bytes
// the returned buffer is static, since it is destroyed by the olm functions it is passed to
// and isnt used again afterwards
void * randomBytes(size_t len);

// format and print JSON data contained in a Str struct
void prettyPrint(Str str);

// load a file, buffer is malloc'd and bufferLen contains the buffer length
// malloc, clear on callsite
bool loadFile(const char *filename, void **buffer, size_t *bufferLen);

bool saveFile(const char *filename, void *buffer, size_t bufferLen);

// olm account
//------------

// malloc, clear on callsite
OlmAccount * createOlmAccount();

// pickle olm account, buffer is malloc'd and bufferLen contains buffer length
// key/keyLen are a key used to encrypt the account
// malloc, clear on callsite
size_t saveOlmAccount(OlmAccount *olmAcc, void **buffer, size_t *bufferLen, const void *key, size_t keyLen);

void loadOlmAccount(OlmAccount *olmAcc, void *buffer, size_t bufferLen, const void *key, size_t keyLen);

// keys
//-----

// get JSON object containing device keys
char * getDeviceKeys(OlmAccount *olmAcc);

// generate nKeys new onetime keys, which are stored in the olm account
// current keys can be received with getOnetimeKeys, used keys are
// removed from account automatically when calling tryNewSession/tryNewSessionFrom
void generateOnetimeKeys(OlmAccount *olmAcc, size_t nKeys);

// get JSON object containing all current onetime keys
char * getOnetimeKeys(OlmAccount *olmAcc);

// get a string that can be uploaded to the server
void getDeviceKeysString(OlmAccount *olmAcc, char *s, size_t n, const char *deviceKeys);

// get JSON object for one onetime key, store in buffer s of length n
void getOnetimeKeyString(OlmAccount *olmAcc, char *s, size_t n, const char *keyId, const char *key);

// get JSON object for one signed onetime key, store in buffer s of length n
void getOnetimeKeyStringSigned(OlmAccount *olmAcc, char *s, size_t n, const char *keyId, const char *key);

// get JSON object for uploading to a server, from a JSON object returned from getOnetimeKeys
void getOnetimeKeysString(OlmAccount *olmAcc, char *s, size_t n, const char *onetimeKeys);

// upload keys to server
// only non-null keys are uploaded
void uploadKeys(HttpCallbacks *http, OlmAccount *olmAcc, const char *deviceKeys, const char *fallbackKeys, const char *onetimeKeys);

// claim a onetime key for the specified device
// free on callsite
Str claimOnetimeKey(HttpCallbacks *http, const char *theirDeviceId);

// matrix session
//---------------

// login with new device, using userId and password, setting deviceDisplayName as the name for the new device
// free on callsite
Str login(HttpCallbacks *http, const char *userId, const char *password, const char *deviceDisplayName);

// olm session
//------------

// create a new Olm session from a claimed key
void createOlmSession(OlmSession *olmSession, OlmAccount *olmAcc, const char *theirDeviceKey, const char *theirOnetimeKey);

// pickle olm account, buffer is malloc'd and bufferLen contains buffer length
// key/keyLen are a key used to encrypt the account
size_t saveOlmSession(OlmSession *olmSession, void **buffer, size_t *bufferLen, const char *key, size_t keyLen);

void loadOlmSession(OlmSession *olmSession, void *buffer, size_t bufferLen, const char *key, size_t keyLen);

// check if a message was encrypted using this OlmSession
size_t checkOlmSession(OlmSession *olmSession, const char *encrypted);

// try establishing a new Olm session
// checks, if the message was encrypted using one of our
// unclaimed onetime keys
size_t tryNewSession(OlmSession *olmSession, OlmAccount *olmAcc, const char *encrypted);

// same as tryNewSession, but checks that the message came from the specified device
size_t tryNewSessionFrom(OlmSession *olmSession, OlmAccount *olmAcc, const char *theirDeviceKey, const char *encrypted);

size_t decrypt(OlmSession *olmSession, const char *encrypted, char *buffer);

size_t encrypt(OlmSession *olmSession, const char *body, char *buffer);

// message events
//---------------

// create olm m.room.encrypted (https://spec.matrix.org/v1.5/client-server-api/#mroomencrypted)
char * createEncryptedOlmEvent(const char *deviceKeyTo, const char *msg, size_t msgLen, const char *deviceIdFrom, const char *deviceKeyFrom);

// create megolm m.room.encrypted (https://spec.matrix.org/v1.5/client-server-api/#mroomencrypted)
char * createEncryptedMegolmEvent(const char *msg, size_t msgLen, const char *deviceIdFrom, const char *deviceKeyFrom, const char *sessionId, size_t sessionIdLen);

// create m.room_key (https://spec.matrix.org/v1.5/client-server-api/#mroom_key)
void generateRoomKeyEvent(
    char *buffer, size_t bufferLen,
    const char *roomId, size_t roomIdLen,
    const char *sessionId, size_t sessionIdLen,
    const char *sessionKey, size_t sessionKeyLen);

// send an event as to-device message
Str sendToDevice(HttpCallbacks *http, const char *userId, const char *deviceId, const char *msgType, const char *msg, size_t msgLen);

Str sendRoomKeyToDevice(
    HttpCallbacks *http,
    OlmSession *olmSess,
    const char *userId,
    const char *deviceIdTo,
    const char *deviceKeyTo,
    const char *deviceIdFrom,
    const char *deviceKeyFrom,
    const char *roomId, size_t roomIdLen,
    const char *sessionId, size_t sessionIdLen,
    const char *sessionKey, size_t sessionKeyLen);

// send a m.room_key_request
Str sendMsgRoomKeyRequest(
    HttpCallbacks *http,
    const char *userId,
    const char *deviceIdTo,
    const char *deviceIdFrom,
    const char *deviceKeyFrom,
    const char *roomId,
    const char *sessionId,
    const char *requestId);

// send a text message to a room
Str sendMsg(HttpCallbacks *http, const char *roomId, const char *msg);

// megolm session
//---------------

// create inbound megolm session from a key received with m.room_key
size_t initInboundGroupSession(OlmInboundGroupSession *session, uint8_t *sessionKey, size_t sessionKeyLen);

// create new outbound megolm session
bool initOutboundGroupSession(OlmOutboundGroupSession *session);

// pickle megolm session, buffer is malloc'd and bufferLen contains buffer length
// key/keyLen are a key used to encrypt the account
size_t saveOutboundGroupSession(OlmOutboundGroupSession *session, void **buffer, size_t *bufferLen, const char *key, size_t keyLen);

void loadOutboundGroupSession(OlmOutboundGroupSession *session, void *buffer, size_t bufferLen, const char *key, size_t keyLen);

// decrypt a received room message
size_t decryptGroup(
    OlmInboundGroupSession *session,
    uint8_t *plaintext, size_t plaintextLen,
    uint8_t *buffer, size_t bufferLen);

// advance megolm messageindex, this is only needed if an outbound megolm session hasnt been saved
// after encrypting/sending a message, which increases the message index internally
void advanceMessageIndex(OlmOutboundGroupSession *session, size_t n);

// encrypt and send room message
Str sendGroupMsg(
    HttpCallbacks *http,
    OlmOutboundGroupSession *session,
    const char *roomId,
    const char *msg);

// verification
//-------------

// verify JSON string
// transform into "canonical JSON", remove "signatures" & "unsigned" fields and then check signature
size_t verify(const char *json, size_t jsonLen, const char *userId, const char *deviceId, const char *deviceKey);

// sign JSON string
void signJson(OlmAccount *olmAcc, char *s, int n, const char *str);

#endif

