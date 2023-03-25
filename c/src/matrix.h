#ifndef MATRIX__H
#define MATRIX__H

#include <stdio.h>

#include <mjson.h>
#include <olm/olm.h>

#include "httpCurl.h"


#define KEY_LEN 100 // 43
#define SIG_LEN 128 // 86
#define TMP_LEN 1024*4

const char *uToken = "syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A";
const char *uId = "@pscho:matrix.org";
const char *dId = "ZGAUCOSULH";
const char *dKey = "5KjCB+kjNlRJhTFxxdfUcr/erraW08V0uZOEe7UYHTM";


// utility
//--------

void checkError(size_t res, OlmAccount *olmAcc) {
    if (res == olm_error()) {
        printf("An error occured: [%d] %s\n",
            olm_account_last_error_code(olmAcc),
            olm_account_last_error(olmAcc));
    }
}

void *
randomBytes(size_t len) {
    uint8_t *random = (uint8_t *)malloc(len); // free on callsite
    for (int i = 0; i < len; i++)
        random[i] = rand() % 256;
    return random;
}

void prettyPrint(const char *s, size_t n) {
    char *printBuf = NULL;
    mjson_pretty(s, n, "  ", mjson_print_dynamic_buf, &printBuf);
    printf("%s\n", printBuf);
    free(printBuf);
}

// olm
//----

OlmAccount *
createOlmAccount() {
    void *olmAccBuffer = malloc(olm_account_size()); // free on callsite
    OlmAccount *olmAcc = olm_account(olmAccBuffer);

    size_t randomLen = olm_create_account_random_length(olmAcc);
    void *randomBuffer = randomBytes(randomLen);

    size_t res = olm_create_account(olmAcc, randomBuffer, randomLen);
    free(randomBuffer);

    checkError(res, olmAcc);

    return olmAcc;
}

void
saveOlmAccount(OlmAccount *olmAcc, const char *filename, const void *key, size_t key_length) {
    size_t buffer_size = olm_pickle_account_length(olmAcc);
    void *buffer = malloc(buffer_size);
    size_t pickled_length =
        olm_pickle_account(olmAcc, key, key_length, buffer, buffer_size);

    FILE *f = fopen(filename, "wb");
    size_t written =
        fwrite(buffer, 1, pickled_length, f);
    if (written != pickled_length)
        printf("Error, only wrote %d out of %d bytes\n", written, pickled_length);
    fclose(f);
    free(buffer);
}

void
loadOlmAccount(OlmAccount *olmAcc, const char *filename, const void *key, size_t key_length) {
    FILE *f = fopen(filename, "rb");
    fseek(f, 0, SEEK_END);
    size_t buffer_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *buffer = malloc(buffer_size);

    size_t read = fread(buffer, 1, buffer_size, f);
    fclose(f);

    if (read != buffer_size)
        printf("Error, only read %d out of %d bytes\n", read, buffer_size);

    size_t res =
        olm_unpickle_account(olmAcc, key, key_length, buffer, read);

    checkError(res, olmAcc);

    free(buffer);
}

void *
getDeviceKeys(OlmAccount *olmAcc) {
    // Allocate buffer and store device keys
    size_t deviceKeyLen = olm_account_identity_keys_length(olmAcc);
    void *deviceKeysBuffer = malloc(deviceKeyLen); // free on callsite
    size_t res = olm_account_identity_keys(olmAcc, deviceKeysBuffer, deviceKeyLen);
    
    checkError(res, olmAcc);

    return deviceKeysBuffer;
}

void
generateOnetimeKeys(OlmAccount *olmAcc, size_t nKeys) {
    size_t randomLen = olm_account_generate_one_time_keys_random_length(olmAcc, nKeys);
    void *randomBuffer = randomBytes(randomLen);

    size_t res = olm_account_generate_one_time_keys(olmAcc, nKeys, randomBuffer, randomLen);
    free(randomBuffer);

    checkError(res, olmAcc);
}

void *
getOnetimeKeys(OlmAccount *olmAcc) {
    size_t onetimeKeysLen = olm_account_one_time_keys_length(olmAcc);
    void *onetimeKeys = malloc(onetimeKeysLen);
    
    size_t res = olm_account_one_time_keys(olmAcc, onetimeKeys, onetimeKeysLen);

    checkError(res, olmAcc);

    return onetimeKeys;
}


void
signJson(OlmAccount *olmAcc, char *s, int n, const char *str) {
    char sig[SIG_LEN]; // TODO: call olm_account_signature_length
    const char *sigKeyId = dId; // TODO: select correct signature key
    size_t res = olm_account_sign(olmAcc, str, strlen(str), sig, SIG_LEN);
    checkError(res, olmAcc);

    char signatureStr[TMP_LEN];
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

// get a string that can be uploaded to the server
void getDeviceKeysString(OlmAccount *olmAcc, char *s, size_t n, const char *deviceKeys) {
    char key_curve25519[KEY_LEN];
    char key_ed25519[KEY_LEN];

    mjson_get_string(deviceKeys, strlen(deviceKeys), "$.curve25519", key_curve25519, KEY_LEN);
    mjson_get_string(deviceKeys, strlen(deviceKeys), "$.ed25519", key_ed25519, KEY_LEN);

    char keysStr[TMP_LEN];
    mjson_snprintf(keysStr, TMP_LEN,
        "{"
            "\"curve25519:%s\":\"%s\","
            "\"ed25519:%s\":\"%s\""
        "}",
        dId, key_curve25519, dId, key_ed25519);

    char unsigRes[TMP_LEN];
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
    char unsigRes[TMP_LEN];
    mjson_snprintf(unsigRes, TMP_LEN,
        "{"
            "\"key\":\"%s\""
        "}", key);
    char signedRes[TMP_LEN];
    signJson(olmAcc, signedRes, TMP_LEN, unsigRes);
    mjson_snprintf(s, n, "{\"signed_curve25519:%s\":%s}", keyId, signedRes);
}

void getOnetimeKeysString(OlmAccount *olmAcc, char *s, size_t n, const char *onetimeKeys) {
    const char *keys;
    int keysLen;
    mjson_find(onetimeKeys, strlen(onetimeKeys), "$.curve25519", &keys, &keysLen); // TODO: maybe generalize to ed25519 (mjson_next \/ )

    char result[TMP_LEN] = "{}";
    char mergeResultStr[TMP_LEN];
    struct mjson_fixedbuf mergeResult = { mergeResultStr, TMP_LEN, 0 };

    int koff, klen, voff, vlen, vtype, off = 0;
    while ((off = mjson_next(keys, keysLen, off, &koff, &klen, &voff, &vlen, &vtype)) != 0) {
        char keyId[TMP_LEN]; // TODO: buffer size
        char key[TMP_LEN];
        sprintf(keyId, "%.*s\0", klen-2, keys + koff+1);
        sprintf(key, "%.*s\0", vlen-2, keys + voff+1);

        char newKeyStr[TMP_LEN];
        getOnetimeKeyStringSigned(olmAcc, newKeyStr, TMP_LEN, keyId, key);

        mjson_merge(result, strlen(result), newKeyStr, strlen(newKeyStr), mjson_print_fixed_buf, &mergeResult);

        strcpy(result, mergeResultStr);
        mergeResult.len = 0;
    }
    strcpy(s, result);
}

// upload keys to server
// only non-null keys are uploaded
void uploadKeys(CURL *curl, OlmAccount *olmAcc, const char *deviceKeys, const char *fallbackKeys, const char *onetimeKeys) {
    char msg[TMP_LEN] = "{ ";

    if (deviceKeys != NULL) {
        char deviceKeysStr[TMP_LEN];
        getDeviceKeysString(olmAcc, deviceKeysStr, TMP_LEN, deviceKeys);

        mjson_snprintf(msg+strlen(msg), TMP_LEN-strlen(msg),
            "\"device_keys\":%s,",
            deviceKeysStr);
    }
    if (fallbackKeys != NULL) {
        char fallbackKeysStr[TMP_LEN];
        getOnetimeKeysString(olmAcc, fallbackKeysStr, TMP_LEN, fallbackKeys);
        
        mjson_snprintf(msg+strlen(msg), TMP_LEN-strlen(msg),
            "\"fallback_keys\":%s,",
            fallbackKeysStr);
    }
    if (onetimeKeys != NULL) {
        char onetimeKeysStr[TMP_LEN];
        getOnetimeKeysString(olmAcc, onetimeKeysStr, TMP_LEN, onetimeKeys);

        mjson_snprintf(msg+strlen(msg), TMP_LEN-strlen(msg),
            "\"one_time_keys\":%s,",
            onetimeKeysStr);
    }

    mjson_snprintf(msg+strlen(msg)-1, TMP_LEN-strlen(msg)+1,
        "}");

    prettyPrint(msg, strlen(msg));

    CurlStr res = curlPost(curl, "https://matrix.org/_matrix/client/r0/keys/upload", msg);
    prettyPrint(res.str, res.size);
    curlStringDelete(&res);
}

CurlStr
login(CURL *curl, const char *userId, const char *password, const char *deviceDisplayName) {
    char msg[TMP_LEN];
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
    CurlStr loginRes =
        curlPost(curl, "https://matrix.org/_matrix/client/v3/login", msg);

    return loginRes;
}

// claim a onetime key for the specified device
CurlStr
claimOnetimeKey(CURL *curl, const char *theirDeviceId) {
    char msg[TMP_LEN];
    mjson_snprintf(msg, TMP_LEN,
        "{"
            "\"one_time_keys\":{"
                "\"@pscho:matrix.org\":{"
                    "\"%s\":\"signed_curve25519\""
                "}"
            "},"
            "\"timeout\":10000"
        "}", theirDeviceId);
    CurlStr res =
        curlPost(curl, "https://matrix.org/_matrix/client/v3/keys/claim",
            msg);
    return res;
}

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

void
loadOlmSession(OlmSession *olmSession, const char *filename, const char *key) {
    FILE *f = fopen(filename, "rb");
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buffer = (char *)malloc(filesize);
    fwrite(buffer, 1, filesize, f);
    fclose(f);
    olm_unpickle_session(olmSession, key, strlen(key), buffer, filesize);
    free(buffer);
}

void
saveOlmSession(OlmSession *olmSession, const char *filename, const char *key) {
    size_t olmSessionBufferLength = olm_pickle_session_length(olmSession);
    void *olmSessionBuffer = malloc(olmSessionBufferLength);
    olm_pickle_session(olmSession, key, strlen(key), olmSessionBuffer, olmSessionBufferLength);
    FILE *f = fopen(filename, "wb");
    fwrite(olmSessionBuffer, 1, olmSessionBufferLength, f);
    fclose(f);
}

// check if a message was encrypted using this OlmSession
size_t
checkOlmSession(OlmSession *olmSession, const char *encrypted) {
    char *buffer = strdup(encrypted);
    size_t res =
        olm_matches_inbound_session(
            olmSession,
            buffer,
            strlen(buffer));

    free(buffer);

    return res;
}

// try establishing a new Olm session
// checks, if the message was encrypted using one of our
// unclaimed onetime keys
size_t
tryNewSession(OlmSession *olmSession, OlmAccount *olmAcc, const char *encrypted) {
    char *buffer = strdup(encrypted);
    size_t res =
        olm_create_inbound_session(olmSession, olmAcc, buffer, strlen(buffer));

    free(buffer);

    return res;
}

// same as tryNewSession, but checks that the message came from the specified device
size_t
tryNewSessionFrom(OlmSession *olmSession, OlmAccount *olmAcc, const char *theirDeviceKey, const char *encrypted) {
    char *buffer = strdup(encrypted);
    size_t res =
        olm_create_inbound_session_from(
            olmSession, olmAcc,
            theirDeviceKey, 43,
            buffer, strlen(buffer));
        
    free(buffer);

    return res;
}

size_t
decrypt(OlmSession *olmSession, const char *encrypted, char *buffer) {
    size_t msgType = 0;

    char *encryptedCopy = strdup(encrypted);

    size_t decryptedBufferMaxLength =
        olm_decrypt_max_plaintext_length(
            olmSession, msgType, encryptedCopy, strlen(encryptedCopy));

    free(encryptedCopy);
    encryptedCopy = strdup(encrypted);

    size_t decryptedBufferLength =
        olm_decrypt(
            olmSession, msgType,
            encryptedCopy, strlen(encryptedCopy),
            buffer, TMP_LEN);

    free(encryptedCopy);

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

// create olm m.encrypted
char *
createEncryptedOlmEvent(const char *deviceKeyTo, const char *msg, size_t msgLen, const char *deviceIdFrom, const char *deviceKeyFrom) {
    char *res = mjson_aprintf(
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
    char *res = mjson_aprintf(
        "{"
                "\"algorithm\":\"m.megolm.v1.aes-sha2\","
                "\"ciphertext\":\"%.*s\","
                "\"device_id\":\"%s\","
                "\"sender_key\":\"%s\","
                "\"session_id\":\"%s\""
        "}",
        msgLen, msg, deviceIdFrom, deviceKeyFrom, sessionId
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
CurlStr
sendToDevice(CURL *curl, const char *userId, const char *deviceId, const char *msgType, const char *msg, size_t msgLen) {
    char url[TMP_LEN];
    sprintf(url, "https://matrix.org/_matrix/client/v3/sendToDevice/%s/%d", msgType, time(NULL));
    char *toDeviceMsg = mjson_aprintf(
         "{"
             "\"messages\":{"
                 "\"%s\":{"
                     "\"%s\":%.*s"
                 "}"
             "}"
         "}",
        userId, deviceId, msgLen, msg);

    CurlStr res = curlPut(curl, url, toDeviceMsg);
    free(toDeviceMsg);

    return res;
}

CurlStr
sendRoomKeyToDevice(
    CURL *curl,
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
    char eventBuffer[TMP_LEN];
    generateRoomKeyEvent(eventBuffer, TMP_LEN,
        roomId, roomIdLen,
        sessionId, sessionIdLen,
        sessionKey, sessionKeyLen);    

    char buffer[TMP_LEN];
    size_t bufferLen =
        encrypt(olmSess, eventBuffer, buffer);

    char *encryptedEvent =
        createEncryptedOlmEvent(
            deviceKeyTo,
            buffer, bufferLen,
            deviceIdFrom, deviceKeyFrom);
    
    printf("sending\n%s\nto %s\n", encryptedEvent, deviceIdTo);

    return sendToDevice(curl,
        userId, deviceIdTo, "m.room.encrypted",
        encryptedEvent, strlen(encryptedEvent));
}

// send a m.room_key_request
CurlStr
sendMsgRoomKeyRequest(
    CURL *curl,
    const char *userId,
    const char *deviceIdTo,
    const char *deviceIdFrom,
    const char *deviceKeyFrom,
    const char *roomId,
    const char *sessionId,
    const char *requestId) {
    char *msg = mjson_aprintf(
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
    return sendToDevice(curl, userId, deviceIdTo, "m.room_key_request", msg, strlen(msg));
}

// send a test message to a room
CurlStr
sendMsg(CURL *curl, const char *roomId, const char *msg) {
    char url[TMP_LEN];
    sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/send/m.room.message/%d", roomId, time(NULL));

    char body[TMP_LEN];
    sprintf(body, "{\"body\":\"%s\",\"msgtype\":\"m.text\"}", msg);

    CurlStr res = curlPut(curl, url, body);
    return res;
}

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

void
loadOutboundGroupSession(OlmOutboundGroupSession *session, const char *filename, const char *key)
{
    FILE *f = fopen(filename, "rb");
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buffer = (char *)malloc(filesize);
    fwrite(buffer, 1, filesize, f);
    fclose(f);
    olm_unpickle_outbound_group_session(session, key, strlen(key), buffer, filesize);
    free(buffer);
}

void
saveOutboundGroupSession(OlmOutboundGroupSession *session, const char *filename, const char *key)
{
    size_t olmSessionBufferLength = olm_pickle_outbound_group_session_length(session);
    void *olmSessionBuffer = malloc(olmSessionBufferLength);
    olm_pickle_outbound_group_session(session, key, strlen(key), olmSessionBuffer, olmSessionBufferLength);
    FILE *f = fopen(filename, "wb");
    fwrite(olmSessionBuffer, 1, olmSessionBufferLength, f);
    fclose(f);
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

// encrypt and send room message
void
sendGroupMsg(
    CURL *curl,
    OlmOutboundGroupSession *session,
    const char *roomId,
    const char *msg)
{
    char messageEvent[TMP_LEN];
    mjson_snprintf(messageEvent, TMP_LEN,
        "{"
            "\"type\":\"m.room.message\","
            "\"content\":{\"body\":\"%s\",\"msgtype\":\"m.text\"},"
            "\"room_id\":\"%s\""
        "}",
        msg, roomId);
    
    char message[TMP_LEN];
    size_t messageLen =
        olm_group_encrypt(session,
            (uint8_t *)messageEvent, strlen(messageEvent),
            (uint8_t *)message, TMP_LEN);
    char sessionId[TMP_LEN];
    size_t sessionIdLen =
        olm_outbound_group_session_id(
            session,
            (uint8_t *)sessionId, TMP_LEN);
    char *encryptedMessage =
        createEncryptedMegolmEvent(
            message, messageLen,
            dId, dKey, sessionId, sessionIdLen);

    char url[TMP_LEN];
    sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/send/m.room.encrypted/%d",
        roomId, time(NULL));
    curlPut(curl, url, encryptedMessage);
}

// verify json string
// transform into "canonical JSON", remove "signatures" & "unsigned" fields and then check signature
size_t
verify(const char *json, size_t jsonLen, const char *userId, const char *deviceId, const char *deviceKey) {
    char *compactJson = NULL;
    mjson_pretty(json, strlen(json), "", mjson_print_dynamic_buf, &compactJson);
    OlmUtility *olmUtil = olm_utility(malloc(olm_utility_size()));

    char *canonicalJson = NULL;
    mjson_merge(compactJson, strlen(compactJson), "{\"signatures\":null,\"unsigned\":null}", 36, mjson_print_dynamic_buf, &canonicalJson);
    printf("canonical json: %s\n", canonicalJson);
    free(compactJson);

    char sig[86];
    char sigJsonPath[100];
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
    free(canonicalJson);

    return res;
}

#endif

