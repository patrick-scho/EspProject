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

const char *uToken = "syt_cHNjaG8_AzpSUXrSkMipJEUlghwV_1XTHlk";
const char *uTokenHeaderStr = "Authorization: Bearer syt_cHNjaG8_AzpSUXrSkMipJEUlghwV_1XTHlk";
const char *uId = "@pscho:matrix.org";
const char *deviceId = "TJJJAWJCAM";

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
    
    size_t buffer_size = olm_pickle_account_length(olmAcc);
    void *buffer = malloc(buffer_size);

    size_t read = fread(buffer, 1, buffer_size, f);
    fclose(f);

    if (read != buffer_size)
        printf("Error, only read %d out of %d bytes\n", read, buffer_size);

    olm_unpickle_account(olmAcc, key, key_length, buffer, read);

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
getOnetimeKeys(OlmAccount *olmAcc, size_t nKeys) {
    size_t onetimeKeysLen = olm_account_one_time_keys_length(olmAcc);
    void *onetimeKeys = malloc(onetimeKeysLen);
    
    size_t res = olm_account_one_time_keys(olmAcc, onetimeKeys, onetimeKeysLen);

    checkError(res, olmAcc);

    return onetimeKeys;
}


void
signJson(OlmAccount *olmAcc, char *s, int n, const char *str) {
    char sig[SIG_LEN]; // TODO: call olm_account_signature_length
    const char *sigKeyId = deviceId; // TODO: select correct signature key
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
        deviceId, key_curve25519, deviceId, key_ed25519);

    char unsigRes[TMP_LEN];
    mjson_snprintf(unsigRes, TMP_LEN,
        "{"
            "\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],"
            "\"device_id\":\"%s\","
            "\"keys\":%s,"
            "\"user_id\":\"%s\""
        "}",
        deviceId, keysStr, uId);

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
    char msg[TMP_LEN] = "{";

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

void test_verify(OlmAccount *olmAcc) {
    const char *deviceKeyStr =
    "{                                                                                                                             "
    "    \"algorithms\": [                                                                                                         "
    "      \"m.olm.v1.curve25519-aes-sha2\",                                                                                       "
    "      \"m.megolm.v1.aes-sha2\"                                                                                                "
    "    ],                                                                                                                        "
    "    \"device_id\": \"TJJJAWJCAM\",                                                                                            "
    "    \"keys\": {                                                                                                               "
    "      \"curve25519:TJJJAWJCAM\": \"8aHti5ijZWhdCBnzHvA42ujwpKltcD4VyZVBBdsKaHA\",                                             "
    "      \"ed25519:TJJJAWJCAM\": \"fE6tLl9n1u6Zj53xBfZShYp/S137GM0tXwIKl9fThLA\"                                                 "
    "    },                                                                                                                        "
    "    \"user_id\": \"@pscho:matrix.org\"                                                                                        "
    "}                                                                                                                             ";

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
verify(const char *json, const char *userId, const char *deviceId, const char *deviceKey) {
    char *compactJson = NULL;
    mjson_pretty(json, strlen(json), "", mjson_print_dynamic_buf, &compactJson);
    OlmUtility *olmUtil = olm_utility(malloc(olm_utility_size()));

    char *canonicalJson = NULL;
    mjson_merge(compactJson, strlen(compactJson), "{\"signatures\":null,\"unsigned\":null}", 36, mjson_print_dynamic_buf, &canonicalJson);
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

// "keys": {
//     "curve25519:TJJJAWJCAM": "8aHti5ijZWhdCBnzHvA42ujwpKltcD4VyZVBBdsKaHA",
//     "ed25519:TJJJAWJCAM": "fE6tLl9n1u6Zj53xBfZShYp/S137GM0tXwIKl9fThLA"
// },
// "signatures": {
//     "@pscho:matrix.org": {
//     "ed25519:TJJJAWJCAM": "EFKDCujOh2VMfjjBEScBDz9zK6d6pgmduRpu21XpQUGGz7hoK3lQY9h8Ze1HmGss1BqToGIZzNzhwpQiuyxpCQ"
//     }
// },

char *
encrypt(OlmSession *olmSession, const char *body) {
    char encryptedBody[1024];
    // olm_encrypt_message_length();
    // olm_encrypt_random_length();
    //olm_encrypt(olmSession, body, strlen(body), random, randomLen, encryptedBody, 1024);
    return mjson_aprintf(
        "{                                                        "
        "    \"type\": \"m.room.encrypted\",                      "
        "    \"content\": {                                       "
        "        \"algorithm\": \"m.olm.v1.curve25519-aes-sha2\", "
        "        \"sender_key\": \"%s\",                          "
        "        \"ciphertext\": {                                "
        "            \"%s\": {                                    "
        "                \"type\": 0,                             "
        "                \"body\": %s                             "
        "            }                                            "
        "        }                                                "
        "    }                                                    "
        "}                                                        ",
        "8aHti5ijZWhdCBnzHvA42ujwpKltcD4VyZVBBdsKaHA",
        "0kFtwQv01nwh6NAcRfReCLvoFX/eUmeFMVmMPrBXbG8",
        encryptedBody);
}

/*
Plan:
08.03: refactor into functions, memory management
09.03: add session/device management
10.03: start olm session
11.03: decrypt megolm
*/

int main() {
    srand(time(NULL));

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    
    OlmAccount *olmAcc = createOlmAccount();
    loadOlmAccount(olmAcc, "olmacc.dat", "abcde", 5);

    // createAndUploadKeys(curl, olmAcc);

    // login
    // CurlStr loginRes =
    //     curlPost(curl, "https://matrix.org/_matrix/client/v3/login",
    //         "{                                                   "
    //         "  \"type\": \"m.login.password\",                   "
    //         "  \"identifier\": {                                 "
    //         "    \"type\": \"m.id.user\",                        "
    //         "    \"user\": \"@pscho:matrix.org\"                 "
    //         "  },                                                "
    //         "  \"password\": \"Wc23EbmB9G3faMq\",                "
    //         "  \"initial_device_display_name\": \"ESP32test1\"   "
    //         "}                                                   "
    //     );

    // prettyPrint(loginRes.str, loginRes.size);
    // curlStringDelete(&loginRes);

    const char *roomId = "!UckjQsQFypaAPMoyrT:matrix.org";
    const char *eventId = "$hfGhFzbxLSqBgBevXP0a1y1Uo3ieYDkO2STxOF_2q2Y";

    //CurlStr str = curlPost("https://matrix.org/_matrix/client/r0/register?kind=guest", "{}");

    char url[1000];
    char msg[1000];
    char body[1000];

    // server state

    if (0) {
    CurlStr syncRes = curlGet(curl, "https://matrix.org/_matrix/client/r0/sync");
    const char *to_device_str;
    int to_device_str_len;
    //printf("%.*s\n", syncRes.size, syncRes.str);
    mjson_find(syncRes.str, syncRes.size, "$.to_device", &to_device_str, &to_device_str_len);
    prettyPrint(to_device_str, to_device_str_len);
    curlStringDelete(&syncRes);
    }

    // receive messages

    // sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/context/%s?limit=10",
    //     "!hzjWFevYHfPyGRVYDa:matrix.org",
    //     "$AUX_LhWwdsPYWrN2SO_Bpw_9_I_e52gM4nl1Rly3oaw");
    // CurlStr str = curlGet(curl, url);
    // // char test[100];
    // // mjson_get_string(str.str, str.size, "$.event.content.body", test, 100);
    // // printf("%s\n", test);
    // prettyPrint(str.str, str.size);
    // curlStringDelete(&str);


    // get room user/device list
    
    if (0) {
    CurlStr membersRes = curlPost(curl, "https://matrix.org/_matrix/client/v3/keys/query", "{\"device_keys\":{\"@pscho:matrix.org\":[]}}");
    prettyPrint(membersRes.str, membersRes.size);
    curlStringDelete(&membersRes);
    }

    // test_verify(olmAcc);

    // claim key
    // CurlStr keysClaimRes =
    //     curlPost(curl, "https://matrix.org/_matrix/client/v3/keys/claim",
    //         "{"
    //             "\"one_time_keys\":{"
    //                 "\"@pscho:matrix.org\":{"
    //                     "\"KHTBDQUCSC\":\"signed_curve25519\""
    //                 "}"
    //             "},"
    //             "\"timeout\":10000"
    //         "}");
    // prettyPrint(keysClaimRes.str, keysClaimRes.size);
    // curlStringDelete(&keysClaimRes);

    /*
    {
        "one_time_keys": {
            "@pscho:matrix.org": {
                "KHTBDQUCSC": {
                    "signed_curve25519:AAAABA": {
                        "key": "bvshxCCBIsIMEnGRR99qdLgiiWE1Ni/W8/YW+wfIzGk",
                        "signatures": {
                            "@pscho:matrix.org": {
                            "ed25519:KHTBDQUCSC": "s6zrM8D4ldCvw7+OkjSxcLUdXRxNe9r6e2yBR1a163a26OpwBVCTUGHujpG3+D012x+16OW0lzmARftO0IVODQ"
                            }
                        }
                    }
                }
            }
        }
    */
    size_t verifyRes =
        verify(
        "{                                                                                                                          "
        "    \"key\": \"bvshxCCBIsIMEnGRR99qdLgiiWE1Ni/W8/YW+wfIzGk\",                                                              "
        "    \"signatures\": {                                                                                                      "
        "        \"@pscho:matrix.org\": {                                                                                           "
        "        \"ed25519:KHTBDQUCSC\": \"s6zrM8D4ldCvw7+OkjSxcLUdXRxNe9r6e2yBR1a163a26OpwBVCTUGHujpG3+D012x+16OW0lzmARftO0IVODQ\" "
        "        }                                                                                                                  "
        "    }                                                                                                                      "
        "}                                                                                                                          ",
        "@pscho:matrix\\.org", "KHTBDQUCSC", "5h4xgfwShdw/My3JhvPArp0pvKQLfKdSaMylyNQps1M"
        );

    printf("verifyRes: %d\n", verifyRes);

    // start olm session
    OlmSession *olmSession = olm_session(malloc(olm_session_size()));

    // start new olm session
    if (0) {
    void *olmSessionRandom = randomBytes(olm_create_outbound_session_random_length(olmSession));
    size_t olmSessionRes =
        olm_create_outbound_session(
            olmSession, olmAcc,
            "5h4xgfwShdw/My3JhvPArp0pvKQLfKdSaMylyNQps1M", 43,
            "bvshxCCBIsIMEnGRR99qdLgiiWE1Ni/W8/YW+wfIzGk", 43,
            olmSessionRandom, olm_create_outbound_session_random_length(olmSession));
    
    printf("olmSessionRes: %d\n", olmSessionRes);
    size_t olmSessionBufferLength = olm_pickle_session_length(olmSession);
    void *olmSessionBuffer = malloc(olmSessionBufferLength);
    olm_pickle_session(olmSession, "abcde", 5, olmSessionBuffer, olmSessionBufferLength);
    printf("%.*s\n", olmSessionBufferLength, olmSessionBuffer);
    }

    // restore session
    // session: I4Ho3e/pPUStITXQ/OLMez0axmtQD4KOpPeMdv1o2tyvAkXVknKgpbZatpqQq1C0wudFtJQ4ISKDCnuUyN6Sfkw0kZSKqxpSCQH1v07cEhlRSILA9qqufXA9xiHPMw38fj63NBDNfYU074SlAPiV+PljhUgoGXMfVJlPXeUsgZwSfcs6RBRvHaaafdQE+buxK5LsQjJmTcu93XyQNVnOR5RMy39HExZtEebevsRunW/6sl0Sg8UySuoZm41uBvpT9KPAKBhx9tzFej1tEEOqKwQWGinzHxzydoStHp7ByglOf4/NmwL+uDLzSnoMB1uurrqRGBMTWEHz+SDGAGHYpjQG0btMlsDo
    char pickledSession[] = "I4Ho3e/pPUStITXQ/OLMez0axmtQD4KOpPeMdv1o2tyvAkXVknKgpbZatpqQq1C0wudFtJQ4ISKDCnuUyN6Sfkw0kZSKqxpSCQH1v07cEhlRSILA9qqufXA9xiHPMw38fj63NBDNfYU074SlAPiV+PljhUgoGXMfVJlPXeUsgZwSfcs6RBRvHaaafdQE+buxK5LsQjJmTcu93XyQNVnOR5RMy39HExZtEebevsRunW/6sl0Sg8UySuoZm41uBvpT9KPAKBhx9tzFej1tEEOqKwQWGinzHxzydoStHp7ByglOf4/NmwL+uDLzSnoMB1uurrqRGBMTWEHz+SDGAGHYpjQG0btMlsDo";
    olm_unpickle_session(olmSession, "", 5, (void *)pickledSession, 352);

    // decrypt olm message
    size_t encryptedBodyLength = 547;
    char onetimeKeyMsgBody1[548] = "Awogh9xP04+ddHkoGp8bmcvAdQ1D82rVDpvVwyfSA2ELujkSIMbuF3n0mCmS/Dql8L5PGb1Ds4ArrHfOWlC4/i6ueelzGiDSQW3BC/TWfCHo0BxF9F4Iu+gVf95SZ4UxWYw+sFdsbyKwAgMKIDYgVNhJjK1HyTMpQnStgblXsPfOsD1yIqtBH7lhh/ZOEAAigAJTJvXw1lyU2ffGJ9CQV3QYCnvERk1bcyborrAKaHr9Gacu7BXHAz8a0yJe6eRyvUdj+DoImb2CRLTOM+XboU/bTRPAXYDLqOqbeqLM3Od29939gt5HIH2bEfp5w0E8stkUT2kIthSbQ0J23UCAEcjjNDCWc9caOy2wI3uIbDLlesdCmjuZXUY1TSJ/4zUN2EYxW4lDrVZsUEU8+UwWn5F83KwUQXL78wpwSZG4xxpn9YXgnoIxOgn5b3fDQKYaRMv8Gga4gVxrNxmViEG0wsPdNnKlYxciyn7YemP6962wKnUkkCCMpuRQVKbUfMJSUFfWqNbhAHIeYpMxvm/WzQoY46Nh4rnGwr4";
    char onetimeKeyMsgBody2[548] = "Awogh9xP04+ddHkoGp8bmcvAdQ1D82rVDpvVwyfSA2ELujkSIMbuF3n0mCmS/Dql8L5PGb1Ds4ArrHfOWlC4/i6ueelzGiDSQW3BC/TWfCHo0BxF9F4Iu+gVf95SZ4UxWYw+sFdsbyKwAgMKIDYgVNhJjK1HyTMpQnStgblXsPfOsD1yIqtBH7lhh/ZOEAAigAJTJvXw1lyU2ffGJ9CQV3QYCnvERk1bcyborrAKaHr9Gacu7BXHAz8a0yJe6eRyvUdj+DoImb2CRLTOM+XboU/bTRPAXYDLqOqbeqLM3Od29939gt5HIH2bEfp5w0E8stkUT2kIthSbQ0J23UCAEcjjNDCWc9caOy2wI3uIbDLlesdCmjuZXUY1TSJ/4zUN2EYxW4lDrVZsUEU8+UwWn5F83KwUQXL78wpwSZG4xxpn9YXgnoIxOgn5b3fDQKYaRMv8Gga4gVxrNxmViEG0wsPdNnKlYxciyn7YemP6962wKnUkkCCMpuRQVKbUfMJSUFfWqNbhAHIeYpMxvm/WzQoY46Nh4rnGwr4";
    char encryptedBody[548] = "Awogh9xP04+ddHkoGp8bmcvAdQ1D82rVDpvVwyfSA2ELujkSIMbuF3n0mCmS/Dql8L5PGb1Ds4ArrHfOWlC4/i6ueelzGiDSQW3BC/TWfCHo0BxF9F4Iu+gVf95SZ4UxWYw+sFdsbyKwAgMKIDYgVNhJjK1HyTMpQnStgblXsPfOsD1yIqtBH7lhh/ZOEAAigAJTJvXw1lyU2ffGJ9CQV3QYCnvERk1bcyborrAKaHr9Gacu7BXHAz8a0yJe6eRyvUdj+DoImb2CRLTOM+XboU/bTRPAXYDLqOqbeqLM3Od29939gt5HIH2bEfp5w0E8stkUT2kIthSbQ0J23UCAEcjjNDCWc9caOy2wI3uIbDLlesdCmjuZXUY1TSJ/4zUN2EYxW4lDrVZsUEU8+UwWn5F83KwUQXL78wpwSZG4xxpn9YXgnoIxOgn5b3fDQKYaRMv8Gga4gVxrNxmViEG0wsPdNnKlYxciyn7YemP6962wKnUkkCCMpuRQVKbUfMJSUFfWqNbhAHIeYpMxvm/WzQoY46Nh4rnGwr4";
    size_t inboundSessionRes =
        olm_matches_inbound_session(
            olmSession,
            onetimeKeyMsgBody1,
            encryptedBodyLength);

    if (inboundSessionRes == 0) {
        printf("session did not match\n");
        inboundSessionRes =
            olm_create_inbound_session_from(
                olmSession, olmAcc,
                "0kFtwQv01nwh6NAcRfReCLvoFX/eUmeFMVmMPrBXbG8", 43,
                onetimeKeyMsgBody2, encryptedBodyLength);
        if (inboundSessionRes == 1) {
            printf("remove onetime keys: %d\n",
                olm_remove_one_time_keys(olmAcc, olmSession));
        }
    }
    if (inboundSessionRes == 1) {
        size_t msgType = 0;
        printf("before: %s\n", encryptedBody);
        size_t decryptedBufferMaxLength = olm_decrypt_max_plaintext_length(olmSession, msgType, encryptedBody, encryptedBodyLength);
        printf("after: %s\n", encryptedBody);
        char *decryptedBuffer = (char *)malloc(decryptedBufferMaxLength);
        size_t decryptedBufferLength =
            olm_decrypt(olmSession, msgType, encryptedBody, encryptedBodyLength, decryptedBuffer, decryptedBufferMaxLength);
        printf("[%d] %.*s\n", decryptedBufferLength, decryptedBufferLength, decryptedBuffer);
    }
    else if (inboundSessionRes == olm_error()) {
        printf("Error: %s\n",
            olm_session_last_error(olmSession));
    }
    else if (inboundSessionRes == 0) {
        printf("still did not match\n");
    }


    if (0) {
    // encrypt dummy message
    char dummyMsg[] =
        "{                                    "
        "    \"messages\": {                  "
        "        \"@pscho:matrix.org\": {     "
        "            \"KHTBDQUCSC\": {        "
        "                \"content\": {},     "
        "                \"type\": \"m.dummy\""
        "            }                        "
        "        }                            "
        "    }                                "
        "}                                    ";
    size_t encryptRandomLength = olm_encrypt_random_length(olmSession);
    void *encryptRandom = randomBytes(encryptRandomLength);
    size_t encryptedLength = olm_encrypt_message_length(olmSession, strlen(dummyMsg));
    void *encrypted = malloc(encryptedLength);

    size_t encryptedWritten =
        olm_encrypt(
            olmSession,
            dummyMsg, strlen(dummyMsg),
            encryptRandom, encryptRandomLength,
            encrypted, encryptedLength);

    printf("[%d/%d]\n%.*s\n", encryptedWritten, encryptedLength, encryptedLength, encrypted);

    // build m.room.encrypted
    // KHTBDQUCSC because curve key in to_device
    char *roomEncrypted = mjson_aprintf(
        "{                                                    "
        "    \"algorithm\": \"m.olm.v1.curve25519-aes-sha2\", "
        "    \"ciphertext\": {                                "
        "       \"%.*s\": \"%.*s\"                                "
        "    },                                               "
        "    \"device_id\": \"%.*s\",                         "
        "    \"sender_key\": \"%.*s\"                         "
        "}                                                    ",
        43, "0kFtwQv01nwh6NAcRfReCLvoFX/eUmeFMVmMPrBXbG8",
        encryptedLength, encrypted,
        strlen(deviceId), deviceId,
        43, "8aHti5ijZWhdCBnzHvA42ujwpKltcD4VyZVBBdsKaHA"
    );

    // send to_device

    sprintf(url, "https://matrix.org/_matrix/client/v3/sendToDevice/%s/%d", "m.room.encrypted", time(NULL));
    char *toDeviceMsg = mjson_aprintf(
        "{                                                                                       "
        "    \"messages\": {                                                                     "
        "        \"@pscho:matrix.org\": {                                                        "
        "            \"KHTBDQUCSC\": %s                                                          "
        "        }                                                                               "
        "    }                                                                                   "
        "}                                                                                       ",
        roomEncrypted);
    CurlStr dummyRes = curlPut(curl, url, toDeviceMsg);
    prettyPrint(dummyRes.str, dummyRes.size);

    // send m.room_key_request to device
    sprintf(url, "https://matrix.org/_matrix/client/v3/sendToDevice/%s/%d", "m.room_key_request", time(NULL));
    CurlStr roomKeyReqRes = curlPut(curl, url,
        "{                                                                                       "
        "    \"messages\": {                                                                     "
        "        \"@pscho:matrix.org\": {                                                        "
        "            \"KHTBDQUCSC\": {                                                           "
        "                \"content\": {                                                          "
        "                   \"action\": \"request\",                                             "
        "                   \"body\": {                                                          "
        "                       \"algorithm\": \"m.megolm.v1.aes-sha2\",                         "
        "                       \"room_id\": \"!hzjWFevYHfPyGRVYDa:matrix.org\",                 "
        "                       \"sender_key\": \"8aHti5ijZWhdCBnzHvA42ujwpKltcD4VyZVBBdsKaHA\", "
        "                       \"session_id\": \"+cKoR984Nqp0zn0a/b5xVsvKThV1xCa8GTnGBHkpfg0\"  "
        "                   },                                                                   "
        "                   \"request_id\": \"abc\",                                             "
        "                   \"requesting_device_id\": \"TJJJAWJCAM\"                             "
        "                },                                                                      "
        "                \"type\": \"m.room_key_request\"                                        "
        "            }                                                                           "
        "        }                                                                               "
        "    }                                                                                   "
        "}                                                                                       "
    );

    prettyPrint(roomKeyReqRes.str, roomKeyReqRes.size);
    curlStringDelete(&roomKeyReqRes);
    }


    while (0) {
        sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/send/m.room.message/%d", roomId, time(NULL));

        getLine(msg, 1000);

        if (strcmp(msg, "/quit") == 0)
            break;

        sprintf(body, "{ \"body\": \"%s\", \"msgtype\": \"m.text\" }", msg);

        puts(body);

        CurlStr str = curlPut(curl, url, body);
        curlStringPrint(&str);
        curlStringDelete(&str);
    }

    puts("done");

    // save_olm_account(olmAcc, "olmacc.dat", "abcde", 5);
    free((void *)olmAcc);

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}