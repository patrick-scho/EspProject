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

const char *uToken = "syt_cHNjaG8_lPLjYLphLXBJVgTBbsEn_1tVbV1";
const char *uTokenHeaderStr = "Authorization: Bearer syt_cHNjaG8_lPLjYLphLXBJVgTBbsEn_1tVbV1";
const char *uId = "@psch:matrix.org";
const char *deviceId = "JLAFKJWSCS";




typedef struct {
    char *str;
    size_t size, capacity, pos;
} CurlStr;
CurlStr curlStringFromStr(const char *str) {
    CurlStr result;
    strcpy(result.str, str);
    result.size = strlen(str);
    result.capacity = result.size;
    result.pos = 0;
    return result;
}
CurlStr curlStringNew() {
    CurlStr result;
    result.str = calloc(100, 1); // free on callsite
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
    curlStr->str = realloc(curlStr->str, newSize);
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
        
        curl_easy_setopt(curl, CURLOPT_PUT, 1L);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, curlReadString);
        curl_easy_setopt(curl, CURLOPT_READDATA, &readStr);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE, readStr.size);
    
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

void getline(char *buffer, size_t size) {
    int i = 0;
    char c = getchar();
    while (c != '\n' && i < size-1) {
        buffer[i++] = c;
        c = getchar();
    }
    buffer[i] = '\0';
}



void check_error(size_t res, OlmAccount *olmAcc) {
    if (res == olm_error()) {
        printf("An error occured: [%d] %s\n",
            olm_account_last_error_code(olmAcc),
            olm_account_last_error(olmAcc));
    }
}

void *
random_bytes(size_t len) {
    uint8_t *random = (uint8_t *)malloc(len); // free on callsite
    for (int i = 0; i < len; i++)
        random[i] = rand() % 256;
    return random;
}

OlmAccount *
create_olm_account() {
    void *olmAccBuffer = malloc(olm_account_size()); // free on callsite
    OlmAccount *olmAcc = olm_account(olmAccBuffer);

    size_t randomLen = olm_create_account_random_length(olmAcc);
    void *randomBuffer = random_bytes(randomLen);

    size_t res = olm_create_account(olmAcc, randomBuffer, randomLen);
    free(randomBuffer);

    check_error(res, olmAcc);

    return olmAcc;
}

void *
create_device_keys(OlmAccount *olmAcc) {
    // Allocate buffer and store device keys
    size_t deviceKeyLen = olm_account_identity_keys_length(olmAcc);
    void *deviceKeysBuffer = malloc(deviceKeyLen); // free on callsite
    size_t res = olm_account_identity_keys(olmAcc, deviceKeysBuffer, deviceKeyLen);
    
    check_error(res, olmAcc);

    return deviceKeysBuffer;
}

void *
create_onetime_keys(OlmAccount *olmAcc, size_t nKeys) {
    size_t randomLen = olm_account_generate_one_time_keys_random_length(olmAcc, nKeys);
    void *randomBuffer = random_bytes(randomLen);

    size_t res = olm_account_generate_one_time_keys(olmAcc, nKeys, randomBuffer, randomLen);
    free(randomBuffer);

    check_error(res, olmAcc);

    size_t onetimeKeysLen = olm_account_one_time_keys_length(olmAcc);
    void *onetimeKeys = malloc(onetimeKeysLen);
    res = olm_account_one_time_keys(olmAcc, onetimeKeys, onetimeKeysLen);

    olm_account_mark_keys_as_published(olmAcc);

    check_error(res, olmAcc);

    return onetimeKeys;
}

void
signJson(OlmAccount *olmAcc, char *s, size_t n, const char *str) {
    char sig[SIG_LEN]; // TODO: call olm_account_signature_length
    const char *sigKeyId = deviceId; // TODO: select correct signature key
    size_t res = olm_account_sign(olmAcc, str, strlen(str), sig, SIG_LEN);
    check_error(res, olmAcc);

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
            "\"user_id\":\"3\""
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

void upload_keys(CURL *curl, OlmAccount *olmAcc, const char *deviceKeys, const char *fallbackKeys, const char *onetimeKeys) {
    char deviceKeysStr[TMP_LEN];
    getDeviceKeysString(olmAcc, deviceKeysStr, TMP_LEN, deviceKeys);
    char fallbackKeysStr[TMP_LEN];
    getOnetimeKeysString(olmAcc, fallbackKeysStr, TMP_LEN, fallbackKeys);
    char onetimeKeysStr[TMP_LEN];
    getOnetimeKeysString(olmAcc, onetimeKeysStr, TMP_LEN, onetimeKeys);

    char msg[TMP_LEN];
    mjson_snprintf(msg, TMP_LEN,
        "{\n"
        "  \"device_keys\": %s,\n"
        "  \"fallback_keys\": %s,\n"
        "  \"one_time_keys\": %s\n"
        "}",
        deviceKeysStr,
        fallbackKeysStr,
        onetimeKeysStr);

    char printBuf[TMP_LEN];
    struct mjson_fixedbuf printRes = { printBuf, TMP_LEN, 0 };
    mjson_pretty(msg, strlen(msg), "  ", mjson_print_fixed_buf, &printRes);
    printf("%s\n", printBuf);

    // CurlStr res = curlPost(curl, "https://matrix.org/_matrix/client/r0/keys/upload", msg);
    // curlStringPrint(&res);
    // curlStringDelete(&res);
}

void olm() {
    OlmAccount *olmAcc = create_olm_account();
    
    void *deviceKeys = create_device_keys(olmAcc);
    void *fallbackKeys = create_onetime_keys(olmAcc, 2);
    void *onetimeKeys = create_onetime_keys(olmAcc, 2);

    upload_keys(NULL, olmAcc, deviceKeys, fallbackKeys, onetimeKeys);

    free(deviceKeys);
    free(fallbackKeys);
    free(onetimeKeys);

    free((void *)olmAcc);
}

int main() {
    srand(time(NULL));

    olm();
    return 0;


    const char *roomId = "!koVStwyiiKcBVbXZYz:matrix.org";
    const char *eventId = "$CyzpX6SWvcUEVl1ANwa4oJduLCCIybikji2cHok1Ww8";
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();

    //CurlStr str = curlPost("https://matrix.org/_matrix/client/r0/register?kind=guest", "{}");

    char url[1000];
    char msg[1000];
    char body[1000];

    sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/context/%s?limit=100", roomId, eventId);

    CurlStr str = curlGet(curl, url);
    char test[100];
    mjson_get_string(str.str, str.size, "$.event.content.body", test, 100);
    printf("%s\n", test);
    curlStringDelete(&str);

    while (1) {
        sprintf(url, "https://matrix.org/_matrix/client/r0/rooms/%s/send/m.room.message/%d", roomId, time(NULL));

        getline(msg, 1000);

        if (strcmp(msg, "/quit") == 0)
            break;

        sprintf(body, "{ \"body\": \"%s\", \"msgtype\": \"m.text\" }", msg);

        puts(body);

        CurlStr str = curlPut(curl, url, body);
        curlStringPrint(&str);
        curlStringDelete(&str);
    }
    
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}