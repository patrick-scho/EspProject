#include "matrix.h"

#include <time.h>
#include <stdio.h>

#include "httpStruct.h"



// utility
//--------

void checkAccountError(OlmAccount *olmAcc, size_t res) {
    if (res == olm_error()) {
        printf("An error occured: [%d] %s\n",
            olm_account_last_error_code(olmAcc),
            olm_account_last_error(olmAcc));
    }
}

void checkSessionError(OlmSession *olmSess, size_t res) {
    if (res == olm_error()) {
        printf("An error occured: [%d] %s\n",
            olm_session_last_error_code(olmSess),
            olm_session_last_error(olmSess));
    }
}

void checkOutboundSessionError(OlmOutboundGroupSession *olmOutboundSess, size_t res) {
    if (res == olm_error()) {
        printf("An error occured: [%d] %s\n",
            olm_outbound_group_session_last_error_code(olmOutboundSess),
            olm_outbound_group_session_last_error(olmOutboundSess));
    }
}

void *
randomBytes(size_t len) {
    static uint8_t random[RND_LEN];
    for (int i = 0; i < len; i++)
        random[i] = rand() % 256;
    return random;
}

void prettyPrint(Str str) {
    char *printBuf = NULL;
    mjson_pretty(str.str, str.len, "  ", mjson_print_dynamic_buf, &printBuf);
    printf("%s\n", printBuf);
    free(printBuf);
}

// clear "buffer" on callsite
bool
loadFile(const char *filename, void **buffer, size_t *bufferLen)
{
    FILE *f = fopen(filename, "rb");
    fseek(f, 0, SEEK_END);
    *bufferLen = ftell(f);
    fseek(f, 0, SEEK_CUR);

    *buffer = malloc(*bufferLen);
    size_t read =
        fread(*buffer, 1, *bufferLen, f);

    fclose(f);

    return read == *bufferLen;
}

bool
saveFile(const char *filename, void *buffer, size_t bufferLen)
{
    FILE *f = fopen(filename, "wb");

    size_t written =
        fwrite(buffer, 1, bufferLen, f);

    fclose(f);

    return written == bufferLen;
}

// olm account
//------------

// clear return value on callsite
OlmAccount *
createOlmAccount() {
    void *olmAccBuffer = malloc(olm_account_size());
    OlmAccount *olmAcc = olm_account(olmAccBuffer);

    size_t randomLen = olm_create_account_random_length(olmAcc);
    void *randomBuffer = randomBytes(randomLen);

    size_t res = olm_create_account(olmAcc, randomBuffer, randomLen);

    checkAccountError(olmAcc, res);

    return olmAcc;
}

// clear "buffer" on callsite
size_t
saveOlmAccount(OlmAccount *olmAcc, void **buffer, size_t *bufferLen, const void *key, size_t keyLen) {
    *bufferLen = olm_pickle_account_length(olmAcc);
    *buffer = malloc(*bufferLen);
    size_t pickledLen =
        olm_pickle_account(olmAcc, key, keyLen, *buffer, *bufferLen);

    checkAccountError(olmAcc, pickledLen);

    return pickledLen;
}

void
loadOlmAccount(OlmAccount *olmAcc, void *buffer, size_t bufferLen, const void *key, size_t keyLen) {
    size_t res =
        olm_unpickle_account(olmAcc, key, keyLen, buffer, bufferLen);

    checkAccountError(olmAcc, res);
}

// keys
//-----

char *
getDeviceKeys(OlmAccount *olmAcc) {
    size_t deviceKeyLen = olm_account_identity_keys_length(olmAcc);
    static char deviceKeysBuffer[DEVICE_KEYS_BUF_LEN];
    size_t res = olm_account_identity_keys(olmAcc, deviceKeysBuffer, deviceKeyLen);
    
    checkAccountError(olmAcc, res);

    return deviceKeysBuffer;
}

void
generateOnetimeKeys(OlmAccount *olmAcc, size_t nKeys) {
    size_t randomLen = olm_account_generate_one_time_keys_random_length(olmAcc, nKeys);
    void *randomBuffer = randomBytes(randomLen);

    size_t res = olm_account_generate_one_time_keys(olmAcc, nKeys, randomBuffer, randomLen);

    checkAccountError(olmAcc, res);
}

char *
getOnetimeKeys(OlmAccount *olmAcc) {
    size_t onetimeKeysLen = olm_account_one_time_keys_length(olmAcc);
    static char onetimeKeys[ONETIME_KEYS_BUF_LEN];
    
    size_t res = olm_account_one_time_keys(olmAcc, onetimeKeys, onetimeKeysLen);

    checkAccountError(olmAcc, res);

    return onetimeKeys;
}

// get a string that can be uploaded to the server
void getDeviceKeysString(OlmAccount *olmAcc, char *s, size_t n, const char *deviceKeys) {
    static char key_curve25519[KEY_LEN];
    static char key_ed25519[KEY_LEN];

    mjson_get_string(deviceKeys, strlen(deviceKeys), "$.curve25519", key_curve25519, KEY_LEN);
    mjson_get_string(deviceKeys, strlen(deviceKeys), "$.ed25519", key_ed25519, KEY_LEN);

    static char keysStr[TMP_LEN];
    mjson_snprintf(keysStr, TMP_LEN,
        "{"
            "\"curve25519:%s\":\"%s\","
            "\"ed25519:%s\":\"%s\""
        "}",
        dId, key_curve25519, dId, key_ed25519);

    static char unsigRes[TMP_LEN];
    mjson_snprintf(unsigRes, TMP_LEN,
        "{"
            "\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],"
            "\"device_id\":\"%s\","
            "\"keys\":%s,"
            "\"user_id\":\"%s\""
        "}",
        dId, keysStr, uId);

    signJson(olmAcc, s, n, unsigRes);
}

// TODO: fallback
void getOnetimeKeyString(OlmAccount *olmAcc, char *s, size_t n, const char *keyId, const char *key) {
    mjson_snprintf(s, n,
        "{"
            "\"curve25519:%s\": \"%s\""
        "}", keyId, key);
}

void getOnetimeKeyStringSigned(OlmAccount *olmAcc, char *s, size_t n, const char *keyId, const char *key) {
    static char unsigRes[TMP_LEN];
    mjson_snprintf(unsigRes, TMP_LEN,
        "{"
            "\"key\":\"%s\""
        "}", key);
    static char signedRes[TMP_LEN];
    signJson(olmAcc, signedRes, TMP_LEN, unsigRes);
    mjson_snprintf(s, n, "{\"signed_curve25519:%s\":%s}", keyId, signedRes);
}

void getOnetimeKeysString(OlmAccount *olmAcc, char *s, size_t n, const char *onetimeKeys) {
    const char *keys;
    int keysLen;
    mjson_find(onetimeKeys, strlen(onetimeKeys), "$.curve25519", &keys, &keysLen); // TODO: maybe generalize to ed25519 (mjson_next \/ )

    static char result[TMP_LEN] = "{}";
    static char mergeResultStr[TMP_LEN];
    struct mjson_fixedbuf mergeResult = { mergeResultStr, TMP_LEN, 0 };

    int koff, klen, voff, vlen, vtype, off = 0;
    while ((off = mjson_next(keys, keysLen, off, &koff, &klen, &voff, &vlen, &vtype)) != 0) {
        static char keyId[TMP_LEN]; // TODO: buffer size
        static char key[TMP_LEN];
        sprintf(keyId, "%.*s\0", klen-2, keys + koff+1);
        sprintf(key, "%.*s\0", vlen-2, keys + voff+1);

        static char newKeyStr[TMP_LEN];
        getOnetimeKeyStringSigned(olmAcc, newKeyStr, TMP_LEN, keyId, key);

        mjson_merge(result, strlen(result), newKeyStr, strlen(newKeyStr), mjson_print_fixed_buf, &mergeResult);

        strcpy_s(result, TMP_LEN, mergeResultStr);
        mergeResult.len = 0;
    }
    strcpy_s(s, n, result);
}

// upload keys to server
// only non-null keys are uploaded
void uploadKeys(HttpCallbacks *http, OlmAccount *olmAcc, const char *deviceKeys, const char *fallbackKeys, const char *onetimeKeys) {
    static char msg[TMP_LEN] = "{ ";

    if (deviceKeys != NULL) {
        static char deviceKeysStr[TMP_LEN];
        getDeviceKeysString(olmAcc, deviceKeysStr, TMP_LEN, deviceKeys);

        mjson_snprintf(msg+strlen(msg), TMP_LEN-strlen(msg),
            "\"device_keys\":%s,",
            deviceKeysStr);
    }
    if (fallbackKeys != NULL) {
        static char fallbackKeysStr[TMP_LEN];
        getOnetimeKeysString(olmAcc, fallbackKeysStr, TMP_LEN, fallbackKeys);
        
        mjson_snprintf(msg+strlen(msg), TMP_LEN-strlen(msg),
            "\"fallback_keys\":%s,",
            fallbackKeysStr);
    }
    if (onetimeKeys != NULL) {
        static char onetimeKeysStr[TMP_LEN];
        getOnetimeKeysString(olmAcc, onetimeKeysStr, TMP_LEN, onetimeKeys);

        mjson_snprintf(msg+strlen(msg), TMP_LEN-strlen(msg),
            "\"one_time_keys\":%s,",
            onetimeKeysStr);
    }

    mjson_snprintf(msg+strlen(msg)-1, TMP_LEN-strlen(msg)+1,
        "}");

    prettyPrint(strInitFromLen(msg, strlen(msg)));

    Str res = http->post(http->data, "https://matrix.org/_matrix/client/r0/keys/upload", strInitFromLen(msg, strlen(msg)));
    prettyPrint(res);
    strFree(&res);
}

// claim a onetime key for the specified device
Str
claimOnetimeKey(HttpCallbacks *http, const char *theirDeviceId) {
    static char msg[TMP_LEN];
    mjson_snprintf(msg, TMP_LEN,
        "{"
            "\"one_time_keys\":{"
                "\"@pscho:matrix.org\":{"
                    "\"%s\":\"signed_curve25519\""
                "}"
            "},"
            "\"timeout\":10000"
        "}", theirDeviceId);
    Str res =
        http->post(http->data, "https://matrix.org/_matrix/client/v3/keys/claim",
            strInitFromLen(msg, strlen(msg)));
    return res;
}

// matrix session
//---------------

Str
login(HttpCallbacks *http, const char *userId, const char *password, const char *deviceDisplayName) {
    static char msg[TMP_LEN];
    mjson_snprintf(msg, TMP_LEN,
            "{"
                "\"type\": \"m.login.password\","
                "\"identifier\": {"
                    "\"type\": \"m.id.user\","
                    "\"user\": \"%s\""
                "},"
                "\"password\": \"%s\","
                "\"initial_device_display_name\": \"%s\""
            "}",
            userId, password, deviceDisplayName
    );
    Str loginRes =
        http->post(http->data, "https://matrix.org/_matrix/client/v3/login", strInitFromLen(msg, strlen(msg)));

    return loginRes;
}

// olm session
//------------

// create a new Olm session from a claimed key
void
createOlmSession(OlmSession *olmSession, OlmAccount *olmAcc, const char *theirDeviceKey, const char *theirOnetimeKey) {
    void *olmSessionRandom = randomBytes(olm_create_outbound_session_random_length(olmSession));
    size_t olmSessionRes =
        olm_create_outbound_session(
            olmSession, olmAcc,
            theirDeviceKey, 43,
            theirOnetimeKey, 43,
            olmSessionRandom,
            olm_create_outbound_session_random_length(olmSession));
}

// free "buffer" on callsite
size_t
saveOlmSession(OlmSession *olmSession, void **buffer, size_t *bufferLen, const char *key, size_t keyLen) {
    size_t olmSessionBufferLength = olm_pickle_session_length(olmSession);
    *buffer = malloc(olmSessionBufferLength);
    *bufferLen =
        olm_pickle_session(olmSession, key, keyLen, *buffer, olmSessionBufferLength);

    checkSessionError(olmSession, *bufferLen);

    return *bufferLen;
}

void
loadOlmSession(OlmSession *olmSession, void *buffer, size_t bufferLen, const char *key, size_t keyLen) {
    size_t result =
        olm_unpickle_session(olmSession, key, keyLen, buffer, bufferLen);
    checkSessionError(olmSession, result);
}

// check if a message was encrypted using this OlmSession
size_t
checkOlmSession(OlmSession *olmSession, const char *encrypted) {
    static char buffer[TMP_LEN];
    strcpy_s(buffer, TMP_LEN, encrypted);
    size_t res =
        olm_matches_inbound_session(
            olmSession,
            buffer,
            strlen(buffer));

    return res;
}

// try establishing a new Olm session
// checks, if the message was encrypted using one of our
// unclaimed onetime keys
size_t
tryNewSession(OlmSession *olmSession, OlmAccount *olmAcc, const char *encrypted) {
    static char buffer[TMP_LEN];
    strcpy_s(buffer, TMP_LEN, encrypted);
    size_t res =
        olm_create_inbound_session(olmSession, olmAcc, buffer, strlen(buffer));

    return res;
}

// same as tryNewSession, but checks that the message came from the specified device
size_t
tryNewSessionFrom(OlmSession *olmSession, OlmAccount *olmAcc, const char *theirDeviceKey, const char *encrypted) {
    static char buffer[TMP_LEN];
    strcpy_s(buffer, TMP_LEN, encrypted);
    size_t res =
        olm_create_inbound_session_from(
            olmSession, olmAcc,
            theirDeviceKey, 43,
            buffer, strlen(buffer));

    return res;
}

size_t
decrypt(OlmSession *olmSession, const char *encrypted, char *buffer) {
    size_t msgType = 0;

    static char encryptedCopy[TMP_LEN];
    strcpy_s(encryptedCopy, TMP_LEN, encrypted);

    size_t decryptedBufferMaxLength =
        olm_decrypt_max_plaintext_length(
            olmSession, msgType, encryptedCopy, strlen(encryptedCopy));

    strcpy_s(encryptedCopy, TMP_LEN, encrypted);

    size_t decryptedBufferLength =
        olm_decrypt(
            olmSession, msgType,
            encryptedCopy, strlen(encryptedCopy),
            buffer, TMP_LEN);

    return decryptedBufferLength;
}

size_t
encrypt(OlmSession *olmSession, const char *body, char *buffer) {
    size_t encryptRandomLength = olm_encrypt_random_length(olmSession);
    void *encryptRandom = randomBytes(encryptRandomLength);
    size_t encryptedLength = olm_encrypt_message_length(
        olmSession, strlen(body));

    size_t encryptedWritten =
        olm_encrypt(
            olmSession,
            body, strlen(body),
            encryptRandom, encryptRandomLength,
            buffer, TMP_LEN);

    return encryptedWritten;
}

// message events
//---------------

// create olm m.encrypted
char *
createEncryptedOlmEvent(const char *deviceKeyTo, const char *msg, size_t msgLen, const char *deviceIdFrom, const char *deviceKeyFrom) {
    static char res[TMP_LEN];
    mjson_snprintf(res, TMP_LEN,
        "{"
                "\"algorithm\":\"m.olm.v1.curve25519-aes-sha2\","
                "\"ciphertext\":{"
                    "\"%s\":{"
                        "\"body\":\"%.*s\","
                        "\"type\":0"
                    "}"
                "},"
                "\"device_id\":\"%s\","
                "\"sender_key\":\"%s\""
        "}",
        deviceKeyTo, msgLen, msg, deviceIdFrom, deviceKeyFrom
    );
    return res;
}

// create megolm m.encrypted
char *
createEncryptedMegolmEvent(const char *msg, size_t msgLen, const char *deviceIdFrom, const char *deviceKeyFrom, const char *sessionId, size_t sessionIdLen) {
    static char res[TMP_LEN];
    mjson_snprintf(res, TMP_LEN,
        "{"
                "\"algorithm\":\"m.megolm.v1.aes-sha2\","
                "\"ciphertext\":\"%.*s\","
                "\"device_id\":\"%s\","
                "\"sender_key\":\"%s\","
                "\"session_id\":\"%.*s\""
        "}",
        msgLen, msg, deviceIdFrom, deviceKeyFrom, sessionIdLen, sessionId
    );
    return res;
}

// m.room_key
void
generateRoomKeyEvent(
    char *buffer, size_t bufferLen,
    const char *roomId, size_t roomIdLen,
    const char *sessionId, size_t sessionIdLen,
    const char *sessionKey, size_t sessionKeyLen)
{
    mjson_snprintf(buffer, bufferLen,
        "{"
            "\"algorithm\":\"m.megolm.v1.aes-sha2\","
            "\"room_id\":\"%.*s\","
            "\"session_id\":\"%.*s\","
            "\"session_key\":\"%.*s\""
        "}",
        // "{"
        //     "\"sender\": \"@pscho:matrix.org\","
        //     "\"sender_device\": \"ZGAUCOSULH\","
        //     "\"keys\": {"
        //         "\"ed25519\": \"7nEQZNvzWOzS1ykLN+xGblGWzeWr+QKIpJ0jd+H+y6A\""
        //     "},"
        //     "\"recipient\": \"@pscho:matrix.org\","
        //     "\"recipient_keys\": {"
        //         "\"ed25519\": \"5h4xgfwShdw/My3JhvPArp0pvKQLfKdSaMylyNQps1M\""
        //     "},"
        //     "\"type\": \"m.room_key\","
        //     "\"content\": {"
        //         "\"algorithm\": \"m.megolm.v1.aes-sha2\","
        //         "\"room_id\": \"%.*s\","
        //         "\"session_id\": \"%.*s\","
        //         "\"session_key\": \"%.*s\","
        //         "\"chain_index\": 0,"
        //         "\"org.matrix.msc3061.shared_history\": true"
        //     "}"
        // "}",
        roomIdLen, roomId,
        sessionIdLen, sessionId,
        sessionKeyLen, sessionKey
    );
}

// send an event as to-device message
Str
sendToDevice(HttpCallbacks *http, const char *userId, const char *deviceId, const char *msgType, const char *msg, size_t msgLen) {
    static char url[URL_LEN];
    sprintf(url, "https://matrix.org/_matrix/client/v3/sendToDevice/%s/%d", msgType, time(NULL));
    static char toDeviceMsg[TMP_LEN];
    mjson_snprintf(toDeviceMsg, TMP_LEN,
         "{"
             "\"messages\":{"
                 "\"%s\":{"
                     "\"%s\":%.*s"
                 "}"
             "}"
         "}",
        userId, deviceId, msgLen, msg);

    Str res = http->put(http->data, url, strInitFromLen(toDeviceMsg, strlen(toDeviceMsg)));

    return res;
}

Str
sendRoomKeyToDevice(
    HttpCallbacks *http,
    OlmSession *olmSess,
    const char *userId,
    const char *deviceIdTo,
    const char *deviceKeyTo,
    const char *deviceIdFrom,
    const char *deviceKeyFrom,
    const char *roomId, size_t roomIdLen,
    const char *sessionId, size_t sessionIdLen,
    const char *sessionKey, size_t sessionKeyLen)
{
    static char eventBuffer[TMP_LEN];
    generateRoomKeyEvent(eventBuffer, TMP_LEN,
        roomId, roomIdLen,
        sessionId, sessionIdLen,
        sessionKey, sessionKeyLen);    

    static char buffer[TMP_LEN];
    size_t bufferLen =
        encrypt(olmSess, eventBuffer, buffer);

    char *encryptedEvent =
        createEncryptedOlmEvent(
            deviceKeyTo,
            buffer, bufferLen,
            deviceIdFrom, deviceKeyFrom);
    
    printf("sending\n%s\nto %s\n", encryptedEvent, deviceIdTo);

    return sendToDevice(http,
        userId, deviceIdTo, "m.room.encrypted",
        encryptedEvent, strlen(encryptedEvent));
}

// send a m.room_key_request
Str
sendMsgRoomKeyRequest(
    HttpCallbacks *http,
    const char *userId,
    const char *deviceIdTo,
    const char *deviceIdFrom,
    const char *deviceKeyFrom,
    const char *roomId,
    const char *sessionId,
    const char *requestId)
{
    static char msg[TMP_LEN];
    mjson_snprintf(msg, TMP_LEN,
        "{"
            "\"content\": {"
               "\"action\": \"request\","
               "\"body\": {"
                   "\"algorithm\": \"m.megolm.v1.aes-sha2\","
                   "\"room_id\": \"%s\","
                   "\"sender_key\": \"%s\","
                   "\"session_id\": \"%s\""
               "},"
               "\"request_id\": \"%s\","
               "\"requesting_device_id\": \"%s \""
            "},"
            "\"type\": \"m.room_key_request\""
        "}",
        roomId, deviceKeyFrom, sessionId, requestId, deviceIdFrom);
    return sendToDevice(http, userId, deviceIdTo, "m.room_key_request", msg, strlen(msg));
}

// send a test message to a room
Str
sendMsg(HttpCallbacks *http, const char *roomId, const char *msg) {
    static char url[URL_LEN];
    sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/send/m.room.message/%d", roomId, time(NULL));

    static char body[TMP_LEN];
    sprintf(body, "{\"body\":\"%s\",\"msgtype\":\"m.text\"}", msg);

    Str res = http->put(http->data, url, strInitFromLen(body, strlen(body)));
    return res;
}

// megolm session
//---------------

// create inbound megolm session from a key received with m.room_key
size_t
initInboundGroupSession(OlmInboundGroupSession *session, uint8_t *sessionKey, size_t sessionKeyLen)
{
    size_t result =
        olm_init_inbound_group_session(
            session,
            sessionKey,
            sessionKeyLen);
            
    return result;
}

// create new outbound megolm session
bool
initOutboundGroupSession(OlmOutboundGroupSession *session)
{
    size_t outboundGroupSessRandomLen = olm_init_outbound_group_session_random_length(session);
    uint8_t *outboundGroupSessRandom = (uint8_t *)randomBytes(outboundGroupSessRandomLen);
    size_t res =
        olm_init_outbound_group_session(session, outboundGroupSessRandom, outboundGroupSessRandomLen);
    return res;
}

// free "buffer" on callsite
size_t
saveOutboundGroupSession(OlmOutboundGroupSession *session, void **buffer, size_t *bufferLen, const char *key, size_t keyLen)
{
    size_t olmSessionBufferLength = olm_pickle_outbound_group_session_length(session);
    *buffer = malloc(olmSessionBufferLength);
    *bufferLen =
        olm_pickle_outbound_group_session(session, key, keyLen, *buffer, olmSessionBufferLength);

    checkOutboundSessionError(session, *bufferLen);

    return *bufferLen;
}

void
loadOutboundGroupSession(OlmOutboundGroupSession *session, void *buffer, size_t bufferLen, const char *key, size_t keyLen)
{
    size_t result =
        olm_unpickle_outbound_group_session(session, key, keyLen, buffer, bufferLen);
    
    checkOutboundSessionError(session, result);
}

// decrypt a received room message
size_t
decryptGroup(
    OlmInboundGroupSession *session,
    uint8_t *plaintext, size_t plaintextLen,
    uint8_t *buffer, size_t bufferLen)
{
    uint32_t messageIndex = 0;

    size_t res = olm_group_decrypt(
        session,
        plaintext, plaintextLen,
        buffer, bufferLen,
        &messageIndex);
    
    return res;
}

void advanceMessageIndex(OlmOutboundGroupSession *session, size_t n) {
    //size_t bufferLen = olm_group_encrypt_message_length(session, 1);
    static uint8_t buffer[128];
    for (int i = 0; i < n; i++) {
        size_t res =
            olm_group_encrypt(session, (uint8_t *)" ", 1, buffer, 128);
        printf("res: %d\nerror: %s\n", res, olm_outbound_group_session_last_error(session));
    }
}

// encrypt and send room message
Str
sendGroupMsg(
    HttpCallbacks *http,
    OlmOutboundGroupSession *session,
    const char *roomId,
    const char *msg)
{
    static char messageEvent[TMP_LEN];
    mjson_snprintf(messageEvent, TMP_LEN,
        "{"
            "\"type\":\"m.room.message\","
            "\"content\":{\"body\":\"%s\",\"msgtype\":\"m.text\"},"
            "\"room_id\":\"%s\""
        "}",
        msg, roomId);

    static char message[TMP_LEN];
    size_t messageLen =
        olm_group_encrypt(session,
            (uint8_t *)messageEvent, strlen(messageEvent),
            (uint8_t *)message, TMP_LEN);

    static char sessionId[TMP_LEN];
    size_t sessionIdLen =
        olm_outbound_group_session_id(
            session,
            (uint8_t *)sessionId, TMP_LEN);
    
    char *encryptedMessage =
        createEncryptedMegolmEvent(
            (const char *)message, messageLen,
            dId, dKey,
            (const char *)sessionId, sessionIdLen);

    static char url[URL_LEN];
    sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/send/m.room.encrypted/%d",
        roomId, time(NULL));
    return http->put(http->data, url, strInitFromLen(encryptedMessage, strlen(encryptedMessage)));
}

// verification
//-------------

// verify json string
// transform into "canonical JSON", remove "signatures" & "unsigned" fields and then check signature
size_t
verify(const char *json, size_t jsonLen, const char *userId, const char *deviceId, const char *deviceKey) {
    static char compactJson[TMP_LEN];
    struct mjson_fixedbuf compactJsonFb = {
        compactJson, TMP_LEN, 0
    };
    mjson_pretty(json, strlen(json), "", mjson_print_fixed_buf, &compactJsonFb);

    OlmUtility *olmUtil = olm_utility(malloc(olm_utility_size()));

    static char canonicalJson[TMP_LEN];
    struct mjson_fixedbuf canonicalJsonFb = {
        canonicalJson, TMP_LEN, 0
    };
    mjson_merge(compactJson, strlen(compactJson), "{\"signatures\":null,\"unsigned\":null}", 36, mjson_print_fixed_buf, &canonicalJsonFb);
    printf("canonical json: %s\n", canonicalJson);

    static char sig[86];
    static char sigJsonPath[100];
    sprintf(sigJsonPath, "$.signatures.%s.ed25519:%s", userId, deviceId);
    mjson_get_string(json, strlen(json), sigJsonPath, sig, 86);
    
    printf("key: %.*s\nsig: %.*s\n",
        43, deviceKey,
        86, sig);
    
    size_t res = olm_ed25519_verify(olmUtil,
        deviceKey, 43,
        canonicalJson, strlen(canonicalJson),
        sig, 86);
    
    if (res == olm_error()) {
        printf("An error has occurred: [%d] %s\n",
            olm_utility_last_error_code(olmUtil),
            olm_utility_last_error(olmUtil));
    }

    free(olmUtil);

    return res;
}

void
signJson(OlmAccount *olmAcc, char *s, int n, const char *str) {
    static char sig[SIG_LEN];
    const char *sigKeyId = dId;
    size_t res = olm_account_sign(olmAcc, str, strlen(str), sig, SIG_LEN);
    checkAccountError(olmAcc, res);

    static char signatureStr[TMP_LEN];
    mjson_snprintf(signatureStr, TMP_LEN,
        "{"
            "\"signatures\":{"
                "\"%s\":{"
                    "\"ed25519:%s\":\"%s\""
                "}"
            "}"
        "}",
        uId, sigKeyId, sig);

    struct mjson_fixedbuf result = { s, n, 0 };
    mjson_merge(str, strlen(str), signatureStr, strlen(signatureStr), mjson_print_fixed_buf, &result);
}
