#ifndef HTTP_STRUCT__H
#define HTTP_STRUCT__H

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char *str;
    size_t len, cap;
    bool allocated;
} Str;

static Str strDup(Str str)
{
    Str result;
    result.str = (char *)malloc(str.len);
    strncpy(result.str, str.str, str.len);
    result.len = str.len;
    result.cap = str.len;
    result.allocated = true;
    return result;
}

static Str strInitFromCap(const char *str, size_t len, size_t cap)
{
    Str result;
    result.str = (char *)str;
    result.len = len;
    result.cap = cap;
    result.allocated = false;
    return result;
}

static Str strInitFromLen(const char *str, size_t len)
{
    return strInitFromCap(str, len, len);
}


static Str strInitFrom(const char *str)
{
    return strInitFromLen(str, strlen(str));
}

static Str strInit()
{
    return strInitFromLen(NULL, 0);
}

static Str strNew()
{
    return strDup(strInit());
}

static void strFree(Str *str)
{
    if (str->allocated)
        free(str->str);
    (*str) = strInit();
}

static void strExtend(Str *str, size_t extendBy)
{
    if (str->allocated)
    {
        str->str = (char *)realloc(str->str, str->len + extendBy);
        str->cap = str->len + extendBy;
    }
    else
    {
        char *mem = (char *)malloc(str->len + extendBy);
        strncpy(mem, str->str, str->len);
        str->str = mem;
        str->cap += str->len + extendBy;
    }
}

static void strAppend(Str *str1, Str str2)
{
    if (str1->cap < str1->len + str2.len)
        strExtend(str1, str2.len);
    size_t offset = str1->len;
    strncpy(str1->str + offset, str2.str, str2.len);
    str1->len = str1->len + str2.len;
}


typedef Str (*HttpGetFn)(void *data, const char *url);
typedef Str (*HttpPutFn)(void *data, const char *url, Str body);
typedef Str (*HttpPostFn)(void *data, const char *url, Str body);

typedef struct {
    void *data;
    HttpGetFn get;
    HttpPutFn put;
    HttpPostFn post;
} HttpCallbacks;

#endif
