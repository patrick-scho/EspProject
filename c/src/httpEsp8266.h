#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>

#include "httpStruct.h"

const char *uTokenHeaderStr = "Authorization: Bearer syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A";

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