#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>

#include <mjson.h>

#include <olm/olm.h>




#define KEY_LEN 100
#define SIG_LEN 128 // 86
#define TMP_LEN 1024*4

const char *uToken = "syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A";
const char *uTokenHeaderStr = "Authorization: Bearer syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A";
const char *uId = "@pscho:matrix.org";
const char *dId = "ZGAUCOSULH";
const char *dKey = "5KjCB+kjNlRJhTFxxdfUcr/erraW08V0uZOEe7UYHTM";

// curl
//-----

typedef struct {
    char *str;
    size_t size, capacity, pos;
} CurlStr;
CurlStr curlStringFromStr(const char *str) {
    CurlStr result;
    //strcpy(result.str, str);
    result.str = strdup(str);
    result.size = strlen(str);
    result.capacity = result.size;
    result.pos = 0;
    return result;
}
CurlStr curlStringNew() {
    CurlStr result;
    result.str = (char *)calloc(100, 1); // free on callsite
    result.size = 0;
    result.capacity = 100;
    result.pos = 0;
    return result;
}
void curlStringDelete(CurlStr *curlStr) {
    free(curlStr->str);
    curlStr->str = NULL;
    curlStr->size = 0;
    curlStr->capacity = 0;
    curlStr->pos = 0;
}
void curlStringExpand(CurlStr *curlStr, size_t amount) {
    size_t newSize = curlStr->capacity + amount;
    curlStr->str = (char *)realloc(curlStr->str, newSize);
    curlStr->capacity = newSize;
}
void curlStringAppend(CurlStr *curlStr, const char *str, size_t amount) {
    size_t remaining = curlStr->capacity - curlStr->size;
    if (remaining < amount) {
        size_t needed = amount - remaining;
        curlStringExpand(curlStr, needed);
    }

    memcpy(curlStr->str + curlStr->size, str, amount);
    curlStr->size += amount;
}
void curlStringPrint(CurlStr *curlStr) {
    printf("%.*s\n", curlStr->size, curlStr->str);
}

size_t curlWriteString(char *ptr, size_t size, size_t nmemb, void *userdata) {
    CurlStr *curlStr = (CurlStr *)userdata;
    
    curlStringAppend(curlStr, ptr, size*nmemb);

    return size*nmemb;
}
size_t curlReadString(char *dst, size_t size, size_t nmemb, void *userdata) {
    CurlStr *curlStr = (CurlStr *)userdata;

    size_t copyAmount = size*nmemb;
    if (copyAmount > (curlStr->size - curlStr->pos)) {
        copyAmount = (curlStr->size - curlStr->pos);
    }

    memcpy(dst, curlStr->str + curlStr->pos, copyAmount);
    curlStr->pos += copyAmount;
    return copyAmount;
}

CURLcode
curlPerform(CURL *curl) {
    struct curl_slist *list = NULL;
    list = curl_slist_append(list, uTokenHeaderStr);
    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    
    CURLcode result = curl_easy_perform(curl);

    curl_slist_free_all(list);

    return result;
}

CurlStr
curlPost(CURL *curl, const char *url, const char *data) {
    CURLcode res;
    
    CurlStr result = curlStringNew();
    
    if(curl) {
        //CurlStr readStr = curlStringFromStr(data);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data));

        //curl_easy_setopt(curl, CURLOPT_READFUNCTION, curlReadString);
        //curl_easy_setopt(curl, CURLOPT_READDATA, &readStr);
    
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curlWriteString);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        res = curlPerform(curl);

        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }
    

    return result;
}


CurlStr
curlPut(CURL *curl, const char *url, const char *data) {
    CURLcode res;
    
    CurlStr result = curlStringNew();

    if(curl) {
        CurlStr readStr = curlStringFromStr(data);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, curlReadString);
        curl_easy_setopt(curl, CURLOPT_READDATA, &readStr);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE, readStr.size);
    
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curlWriteString);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        res = curlPerform(curl);

        curlStringDelete(&readStr);

        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }

    return result;
}

CurlStr
curlGet(CURL *curl, const char *url) {
    CURLcode res;
    
    CurlStr result = curlStringNew();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curlWriteString);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        res = curlPerform(curl);

        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }

    return result;
}

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

size_t
tryNewSession(OlmSession *olmSession, OlmAccount *olmAcc, const char *encrypted) {
    char *buffer = strdup(encrypted);
    size_t res =
        olm_create_inbound_session(olmSession, olmAcc, buffer, strlen(buffer));

    free(buffer);

    return res;
}

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

char *
createMsgEncrypted(const char *deviceKeyTo, const char *msg, size_t msgLen, const char *deviceIdFrom, const char *deviceKeyFrom) {
    char *res = mjson_aprintf(
        "{"
            "\"content\":{"
                "\"algorithm\":\"m.olm.v1.curve25519-aes-sha2\","
                "\"ciphertext\":{"
                    "\"%s\":{"
                        "\"body\":\"%.*s\","
                        "\"type\":0"
                    "}"
                "},"
                "\"device_id\":\"%s\","
                "\"sender_key\":\"%s\""
            "},"
            "\"type\":\"m.room.encrypted\""
        "}",
        deviceKeyTo, msgLen, msg, deviceIdFrom, deviceKeyFrom
    );
    return res;
}

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

CurlStr
sendMsg(CURL *curl, const char *roomId, const char *msg) {
    char url[TMP_LEN];
    sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/send/m.room.message/%d", roomId, time(NULL));

    char body[TMP_LEN];
    sprintf(body, "{\"body\":\"%s\",\"msgtype\":\"m.text\"}", msg);

    CurlStr res = curlPut(curl, url, body);
    return res;
}

void test_verify(OlmAccount *olmAcc) {
    const char *deviceKeyStr =
    "{"
        "\"algorithms\":["
          "\"m.olm.v1.curve25519-aes-sha2\","
          "\"m.megolm.v1.aes-sha2\""
        "],"
        "\"device_id\": \"TJJJAWJCAM\","
        "\"keys\": {"
          "\"curve25519:TJJJAWJCAM\": \"8aHti5ijZWhdCBnzHvA42ujwpKltcD4VyZVBBdsKaHA\","
          "\"ed25519:TJJJAWJCAM\": \"fE6tLl9n1u6Zj53xBfZShYp/S137GM0tXwIKl9fThLA\""
        "},"
        "\"user_id\": \"@pscho:matrix.org\""
    "}";

    char *deviceKeyStr2 = NULL;
    mjson_pretty(deviceKeyStr, strlen(deviceKeyStr), "", mjson_print_dynamic_buf, &deviceKeyStr2);
    printf("[%d] %s\n", strlen(deviceKeyStr2), deviceKeyStr2);
    OlmUtility *olmUtil = olm_utility(malloc(olm_utility_size()));

    
    char sig[86];
    size_t res = olm_account_sign(olmAcc, deviceKeyStr2, strlen(deviceKeyStr2), sig, 86);
    checkError(res, olmAcc);
    printf("%.*s\n", 86, sig);
    // EFKDCujOh2VMfjjBEScBDz9zK6d6pgmduRpu21XpQUGGz7hoK3lQY9h8Ze1HmGss1BqToGIZzNzhwpQiuyxpCQ

    char *devKeys = (char *)getDeviceKeys(olmAcc);

    char key[43];
    mjson_get_string(devKeys, strlen(devKeys), "$.ed25519", key, 43);
    printf("%s\n%.*s\n", devKeys, 43, key);
    
    res = olm_ed25519_verify(olmUtil,
        key, 43,
        deviceKeyStr2, strlen(deviceKeyStr2),
        sig, 86);
    
    if (res == olm_error()) {
        printf("An error has occurred: [%d] %s\n",
            olm_utility_last_error_code(olmUtil),
            olm_utility_last_error(olmUtil));
    }

    printf("res: %d\n", res);
    free(deviceKeyStr2);
    free(olmUtil);
}

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

// cli
//----

void getLine(char *buffer, size_t size) {
    int i = 0;
    char c = getchar();
    while (c != '\n' && i < size-1) {
        buffer[i++] = c;
        c = getchar();
    }
    buffer[i] = '\0';
}

bool command(const char *str, const char *cmd) {
    return
        strncmp(str, cmd, strlen(cmd)) == 0
        && strlen(str) == strlen(cmd);
}

int promptInt(const char *str) {
    printf("%s: ", str);
    int res = 0;
    scanf("%d", &res);
    return res;
}

void promptStr(const char *str, char *buffer) {
    printf("%s: ", str);
    getLine(buffer, TMP_LEN);
}

/*
- upload keys
- claim key
- verify
- start session
- dummy
- key share request
- decrypt
*/

int main() {
    srand(time(NULL));

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    
    OlmAccount *olmAcc = createOlmAccount();
    loadOlmAccount(olmAcc, "olmacc.dat", "abcde", 5);

    OlmSession *olmSess = olm_session(malloc(olm_session_size()));

    char msg[TMP_LEN];

    while (1) {

        getLine(msg, 1000);

        if (command(msg, "quit"))
            break;
        if (command(msg, "upload device keys"))
            uploadKeys(curl, olmAcc, (const char *)getDeviceKeys(olmAcc), NULL, NULL);
        if (command(msg, "upload onetime keys"))
            uploadKeys(curl, olmAcc, NULL, NULL, (const char *)getOnetimeKeys(olmAcc));
        if (command(msg, "generate onetime keys")) {
            int n = promptInt("how many?");
            generateOnetimeKeys(olmAcc, n);
        }
        if (command(msg, "list device keys")) {
            char *keys = (char *)getDeviceKeys(olmAcc);
            prettyPrint(keys, strlen(keys));
        }
        if (command(msg, "list onetime keys")) {
            char *keys = (char *)getOnetimeKeys(olmAcc);
            prettyPrint(keys, strlen(keys));
        }
        if (command(msg, "login")) {
            char userId[TMP_LEN];
            char password[TMP_LEN];
            char name[TMP_LEN];
            promptStr("userId", userId);
            promptStr("password", password);
            promptStr("device display name", name);
            CurlStr res =
                login(curl, userId, password, name);
            prettyPrint(res.str, res.size);
            curlStringDelete(&res);
        }
        if (command(msg, "save olmacc")) {
            char filename[TMP_LEN];
            char key[TMP_LEN];
            promptStr("filename", filename);
            promptStr("key", key);
            saveOlmAccount(olmAcc, filename, key, strlen(key));
        }
        if (command(msg, "load olmacc")) {
            char filename[TMP_LEN];
            char key[TMP_LEN];
            promptStr("filename", filename);
            promptStr("key", key);
            loadOlmAccount(olmAcc, filename, key, strlen(key));
        }
        if (command(msg, "list devices")) {
            CurlStr membersRes = curlPost(curl, "https://matrix.org/_matrix/client/v3/keys/query", "{\"device_keys\":{\"@pscho:matrix.org\":[]}}");
            prettyPrint(membersRes.str, membersRes.size);
            curlStringDelete(&membersRes);
        }
        if (command(msg, "claim onetime key")) {
            char deviceId[TMP_LEN];
            promptStr("device id", deviceId);
            CurlStr onetimeKey = claimOnetimeKey(curl, deviceId);
            prettyPrint(onetimeKey.str, onetimeKey.size);
            curlStringDelete(&onetimeKey);
        }
        if (command(msg, "sync")) {
            CurlStr syncRes = curlGet(curl, "https://matrix.org/_matrix/client/r0/sync");
            //prettyPrint(syncRes.str, syncRes.size);
            //printf("%.*s\n", syncRes.size, syncRes.str);
            FILE *f = fopen("sync.json", "wb");
            fwrite(syncRes.str, 1, syncRes.size, f);
            fclose(f);
            curlStringDelete(&syncRes);
        }
        if (command(msg, "todevice")) {
            CurlStr syncRes = curlGet(curl, "https://matrix.org/_matrix/client/r0/sync");
            const char *to_device_str; int to_device_str_len;
            mjson_find(syncRes.str, syncRes.size, "$.to_device", &to_device_str, &to_device_str_len);
            prettyPrint(to_device_str, to_device_str_len);
            curlStringDelete(&syncRes);
        }
        if (command(msg, "dummy")) {
            char deviceIdTo[TMP_LEN];
            char deviceKeyTo[TMP_LEN];
            promptStr("device id to", deviceIdTo);
            promptStr("device key to", deviceKeyTo);

            char dummyMsg[TMP_LEN];
            mjson_snprintf(dummyMsg, TMP_LEN,
                "{"
                    "\"content\": {},"
                    "\"type\": \"m.dummy\""
                "}",
                deviceIdTo);
            char dummyMsgEncrypted[TMP_LEN];
            size_t dummyMsgEncryptedLen =
                encrypt(olmSess, dummyMsg, dummyMsgEncrypted);
            char *encryptedEvent =
                createMsgEncrypted(deviceKeyTo, dummyMsgEncrypted, dummyMsgEncryptedLen, dId, dKey);
            printf("%s\n", encryptedEvent);
            CurlStr res =
                sendToDevice(curl, uId, deviceIdTo, "m.encrypted", encryptedEvent, strlen(encryptedEvent));
            prettyPrint(res.str, res.size);
            curlStringDelete(&res);
        }
        if (command(msg, "keyshare")) {
            char deviceIdTo[TMP_LEN];
            char roomId[TMP_LEN];
            char sessionId[TMP_LEN];
            char requestId[TMP_LEN];

            promptStr("deviceIdTo", deviceIdTo);
            promptStr("roomId", roomId);
            promptStr("sessionId", sessionId);
            promptStr("requestId", requestId);
            CurlStr res =
                sendMsgRoomKeyRequest(
                    curl,
                    uId,
                    deviceIdTo,
                    dId,
                    dKey,
                    roomId,
                    sessionId,
                    requestId
                );
            prettyPrint(res.str, res.size);
            curlStringDelete(&res);
        }
        if (command(msg, "verify")) {
            char toVerify[TMP_LEN];
            char deviceId[TMP_LEN];
            char deviceKey[TMP_LEN];
            promptStr("toVerify", toVerify);
            promptStr("deviceId", deviceId);
            promptStr("deviceKey", deviceKey);

            size_t verifyRes =
                verify(
                    toVerify, strlen(toVerify),
                    "@pscho:matrix\\.org",
                    deviceId,
                    deviceKey
                );

            printf("verifyRes: %d\n", verifyRes);
        }
        if (command(msg, "encrypt")) {
            char toEncrypt[TMP_LEN];
            promptStr("toEncrypt", toEncrypt);

            char buffer[TMP_LEN];
            size_t len =
                encrypt(olmSess, toEncrypt, buffer);
            
            printf("%.*s\n", len, buffer);
        }
        if (command(msg, "decrypt")) {
            char toDecrypt[TMP_LEN];
            promptStr("toDecrypt", toDecrypt);

            char buffer[TMP_LEN];
            size_t len =
                decrypt(olmSess, toDecrypt, buffer);
            
            printf("%.*s\n", len, buffer);
        }
        if (command(msg, "new session")) {
            char deviceKey[TMP_LEN];
            char onetimeKey[TMP_LEN];
            promptStr("deviceKey", deviceKey);
            promptStr("onetimeKey", onetimeKey);
            createOlmSession(olmSess, olmAcc, deviceKey, onetimeKey);
        }
        if (command(msg, "save session")) {
            if (olmSess == NULL) {
                printf("create session first\n");
            }
            else {
                char filename[TMP_LEN];
                char key[TMP_LEN];
                promptStr("filename", filename);
                promptStr("key", key);
                saveOlmSession(olmSess, filename, key);
            }
        }
        if (command(msg, "load session")) {
            char filename[TMP_LEN];
            char key[TMP_LEN];
            promptStr("filename", filename);
            promptStr("key", key);
            loadOlmSession(olmSess, filename, key);
            // char describeBuffer[600];
            // olm_session_describe(olmSess, describeBuffer, 600);
            // printf("Session loaded:\n%s\n", describeBuffer);
        }
        if (command(msg, "check session")) {
            char encrypted[TMP_LEN];
            promptStr("encrypted", encrypted);

            switch (checkOlmSession(olmSess, encrypted)) {
            case 1: {
                printf("session matched!\n");
                char buffer[TMP_LEN];
                size_t len =
                    decrypt(olmSess, encrypted, buffer);
                break;
            }
            case 0: {
                printf("Session didnt match\n");
                break;
            }
            default: {
                printf("error: %s\n", olm_session_last_error(olmSess));

            }
            }
        }
        if (command(msg, "in session")) {
            char encrypted[TMP_LEN];
            //promptStr("deviceKey", deviceKey);
            promptStr("encrypted", encrypted);
            if (tryNewSession(olmSess, olmAcc, encrypted) != olm_error()) {
                printf("session created!\n");
                olm_remove_one_time_keys(olmAcc, olmSess);
                char buffer[TMP_LEN];
                size_t len =
                    decrypt(olmSess, encrypted, buffer);
            }
            else {
                printf("error: %s\n", olm_session_last_error(olmSess));
            }
        }
        if (command(msg, "in session from")) {
            char deviceKey[TMP_LEN];
            char encrypted[TMP_LEN];
            promptStr("deviceKey", deviceKey);
            promptStr("encrypted", encrypted);
            if (tryNewSessionFrom(olmSess, olmAcc, deviceKey, encrypted) != olm_error()) {
                printf("session created!\n");
                olm_remove_one_time_keys(olmAcc, olmSess);
                char buffer[TMP_LEN];
                size_t len =
                    decrypt(olmSess, encrypted, buffer);
            }
            else {
                printf("error: %s\n", olm_session_last_error(olmSess));
            }
        }
        if (command(msg, "get messages")) {
            char url[TMP_LEN];
            sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/context/%s?limit=10",
                "!hzjWFevYHfPyGRVYDa:matrix.org",
                "$AUX_LhWwdsPYWrN2SO_Bpw_9_I_e52gM4nl1Rly3oaw");
            CurlStr str = curlGet(curl, url);
            const char *msgBody; int msgBodyLen;
            mjson_find(str.str, str.size, "$.event.content.body", &msgBody, &msgBodyLen);
            printf("%.*s\n", msgBodyLen, msgBody);
            prettyPrint(str.str, str.size);
            curlStringDelete(&str);
        }
        if (command(msg, "test")) {
            char sessionKey[TMP_LEN];
            promptStr("Session Key", sessionKey);
            
            OlmInboundGroupSession *inGroupSession =
                olm_inbound_group_session(malloc(olm_inbound_group_session_size()));
            if (olm_init_inbound_group_session(
                    inGroupSession,
                    (uint8_t *)sessionKey,
                    strlen(sessionKey)) != olm_error())
            {
                char message[TMP_LEN];
                promptStr("toDecrypt", message);

                char buffer[TMP_LEN];
                uint32_t messageIndex = 0;

                size_t res = olm_group_decrypt(
                    inGroupSession,
                    (uint8_t *)message, strlen(message),
                    (uint8_t *)buffer, TMP_LEN, &messageIndex);
                if (res == olm_error()) {
                    printf("Error: %s\n",
                        olm_inbound_group_session_last_error(inGroupSession));
                }
                else {
                    size_t bufferLen = res;
                    printf("%.*s\nmessageIndex: %d\n", bufferLen, buffer, messageIndex);
                }
            }
        }
    }

    saveOlmAccount(olmAcc, "olmacc.dat", "abcde", 5);

    puts("done");

    free((void *)olmAcc);

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}