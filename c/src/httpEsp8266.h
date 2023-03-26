#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>


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

const char *uTokenHeaderStr = "Authorization: Bearer syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A";

typedef WiFiClient CURL;

CurlStr
curlPost(CURL *client, const char *url, const char *data) {
    CurlStr result = curlStringNew();

    HTTPClient https;

    if (https.begin(*client, url))
    {
        https.addHeader("Authorization", "Bearer syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A");

        // start connection and send HTTP header
        int httpCode = https.POST(data);

        // httpCode will be negative on error
        if (httpCode > 0)
        {
            // file found at server
            if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
            {
                String payload = https.getString();
                result = curlStringFromStr(payload.c_str());
            }
        }
        else
        {
            Serial.printf("[HTTPS] POST... failed, error: %s\n", https.errorToString(httpCode).c_str());
        }

        https.end();
    }
    else
    {
        Serial.printf("[HTTPS] Unable to connect\n");
    }

    return result;
}


CurlStr
curlPut(CURL *client, const char *url, const char *data) {
    CurlStr result = curlStringNew();

    HTTPClient https;

    if (https.begin(*client, url))
    {
        https.addHeader("Authorization", "Bearer syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A");

        // start connection and send HTTP header
        int httpCode = https.PUT(data);

        // httpCode will be negative on error
        if (httpCode > 0)
        {
            // file found at server
            if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
            {
                String payload = https.getString();
                result = curlStringFromStr(payload.c_str());
            }
        }
        else
        {
            Serial.printf("[HTTPS] PUT... failed, error: %s\n", https.errorToString(httpCode).c_str());
        }

        https.end();
    }
    else
    {
        Serial.printf("[HTTPS] Unable to connect\n");
    }

    return result;
}

CurlStr
curlGet(CURL *client, const char *url) {
    CurlStr result = curlStringNew();

    HTTPClient https;

    if (https.begin(*client, url))
    {
        https.addHeader("Authorization", "Bearer syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A");

        // start connection and send HTTP header
        int httpCode = https.GET();

        // httpCode will be negative on error
        if (httpCode > 0)
        {
            // file found at server
            if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
            {
                String payload = https.getString();
                result = curlStringFromStr(payload.c_str());
            }
        }
        else
        {
            Serial.printf("[HTTPS] GET... failed, error: %s\n", https.errorToString(httpCode).c_str());
        }

        https.end();
    }
    else
    {
        Serial.printf("[HTTPS] Unable to connect\n");
    }

    return result;
}