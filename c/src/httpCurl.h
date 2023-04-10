#ifndef HTTP_CURL__H
#define HTTP_CURL__H

#include <curl.h>

#include "httpStruct.h"


const char *uTokenHeaderStr = "Authorization: Bearer syt_cHNjaG8_qSvBDiGfoNLoypbbQKVB_3CYp5A";

typedef struct {
    Str str;
    size_t pos;
} ReadStr;

size_t curlWriteString(char *ptr, size_t size, size_t nmemb, void *userdata) {
    Str *str = (Str *)userdata;
    
    Str str2 = strDup(strInitFromLen(ptr, size*nmemb));
    strAppend(str, str2);

    return size*nmemb;
}
size_t curlReadString(char *dst, size_t size, size_t nmemb, void *userdata) {
    ReadStr *readStr = (ReadStr *)userdata;

    size_t copyAmount = size*nmemb;
    if (copyAmount > (readStr->str.len - readStr->pos)) {
        copyAmount = (readStr->str.len - readStr->pos);
    }

    memcpy(dst, readStr->str.str + readStr->pos, copyAmount);
    readStr->pos += copyAmount;
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

Str
curlPost(void *data, const char *url, Str body) {
    CURL *curl = (CURL *)data;

    CURLcode res;
    
    Str result = strInit();
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.str);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.len);
    
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteString);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        res = curlPerform(curl);

        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }
    

    return result;
}


Str
curlPut(void *data, const char *url, Str body) {
    CURL *curl = (CURL *)data;

    CURLcode res;
    
    Str result = strInit();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        ReadStr readStr;
        readStr.str = body;
        readStr.pos = 0;

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, curlReadString);
        curl_easy_setopt(curl, CURLOPT_READDATA, &readStr);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE, body.len);
    
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteString);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        res = curlPerform(curl);

        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }

    return result;
}

Str
curlGet(void *data, const char *url) {
    CURL *curl = (CURL *)data;

    CURLcode res;

    Str result = strInit();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteString);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

        res = curlPerform(curl);

        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }

    return result;
}

#endif

