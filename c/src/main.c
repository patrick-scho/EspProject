#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>


#include "matrix.h"
#include "httpCurl.h"


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




int main() {
    srand(time(NULL));

    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    

    OlmAccount *olmAcc = createOlmAccount();
    // load previously stored OlmAccount
    loadOlmAccount(olmAcc, "olmacc.dat", "abcde", 5);

    OlmSession *olmSess = olm_session(malloc(olm_session_size()));

    OlmOutboundGroupSession *outboundGroupSess =
        olm_outbound_group_session(malloc(olm_outbound_group_session_size()));
    OlmInboundGroupSession *inboundGroupSession =
        olm_inbound_group_session(malloc(olm_inbound_group_session_size()));


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
                createEncryptedOlmEvent(deviceKeyTo, dummyMsgEncrypted, dummyMsgEncryptedLen, dId, dKey);
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
        if (command(msg, "in group session")) {
            char sessionKey[TMP_LEN];
            promptStr("Session Key", sessionKey);
            
            olm_init_inbound_group_session(
                inboundGroupSession,
                (uint8_t *)sessionKey,
                strlen(sessionKey));
        }
        if (command(msg, "group decrypt")) {
            char message[TMP_LEN];
            promptStr("toDecrypt", message);

            char buffer[TMP_LEN];
            uint32_t messageIndex = 0;

            size_t res = olm_group_decrypt(
                inboundGroupSession,
                (uint8_t *)message, strlen(message),
                (uint8_t *)buffer, TMP_LEN, &messageIndex);
            if (res == olm_error()) {
                printf("Error: %s\n",
                    olm_inbound_group_session_last_error(inboundGroupSession));
            }
            else {
                size_t bufferLen = res;
                printf("%.*s\nmessageIndex: %d\n", bufferLen, buffer, messageIndex);
            }
        }
        if (command(msg, "create megolm")) {
            char roomId[TMP_LEN];
            promptStr("Room ID", roomId);

            initOutboundGroupSession(outboundGroupSess);

            // get session id and key
            size_t idLen = olm_outbound_group_session_id_length(outboundGroupSess);
            uint8_t *id = (uint8_t *)malloc(idLen);
            olm_outbound_group_session_id(outboundGroupSess, id, idLen);
            size_t keyLen = olm_outbound_group_session_key_length(outboundGroupSess);
            uint8_t *key = (uint8_t *)malloc(keyLen);
            olm_outbound_group_session_key(outboundGroupSess, key, keyLen);

            // create inbound session
            olm_init_inbound_group_session(inboundGroupSession, key, keyLen);
        }
        if (command(msg, "save megolm")) {
            char filename[TMP_LEN];
            char key[TMP_LEN];
            promptStr("filename", filename);
            promptStr("key", key);

            saveOutboundGroupSession(outboundGroupSess, filename, key);
        }
        if (command(msg, "load megolm")) {
            char filename[TMP_LEN];
            char key[TMP_LEN];
            promptStr("filename", filename);
            promptStr("key", key);

            loadOutboundGroupSession(outboundGroupSess, filename, key);
                
            // get session id and key
            size_t sessionIdLen = olm_outbound_group_session_id_length(outboundGroupSess);
            uint8_t *sessionId = (uint8_t *)malloc(sessionIdLen);
            olm_outbound_group_session_id(outboundGroupSess, sessionId, sessionIdLen);
            size_t sessionKeyLen = olm_outbound_group_session_key_length(outboundGroupSess);
            uint8_t *sessionKey = (uint8_t *)malloc(sessionKeyLen);
            olm_outbound_group_session_key(outboundGroupSess, sessionKey, sessionKeyLen);

            printf("key: %.*s id: %.*s\n", sessionKeyLen, sessionKey, sessionIdLen, sessionId);

            // create inbound session
            olm_init_inbound_group_session(inboundGroupSession, sessionKey, sessionKeyLen);
        }
        if (command(msg, "loop devices")) {
            char roomId[TMP_LEN];
            char sessionId[TMP_LEN];
            char sessionKey[TMP_LEN];
            promptStr("roomId", roomId);
            promptStr("sessionId", sessionId);
            promptStr("sessionKey", sessionKey);


            CurlStr devicesRes = curlPost(curl, "https://matrix.org/_matrix/client/v3/keys/query", "{\"device_keys\":{\"@pscho:matrix.org\":[]}}");

            const char *s; int sLen;
            mjson_find(devicesRes.str, devicesRes.size, "$.device_keys.@pscho:matrix\\.org", &s, &sLen);
            int kOff, kLen, vOff, vLen, vType, off;
            for (off = 0; (off = mjson_next(s, sLen, off, &kOff, &kLen,
                          &vOff, &vLen, &vType)) != 0; ) {
                const char *kStr = s + kOff;
                const char *vStr = s + vOff;
                char deviceId[TMP_LEN];
                int deviceIdLen =
                    mjson_get_string(vStr, vLen, "$.device_id", deviceId, TMP_LEN);
                char searchTerm[TMP_LEN];
                sprintf(searchTerm, "$.keys.curve25519:%.*s", deviceIdLen, deviceId);
                char deviceKey[TMP_LEN];
                int deviceKeyLen =
                    mjson_get_string(vStr, vLen, searchTerm, deviceKey, TMP_LEN);

                printf("device key: %.*s\tdevice id: %.*s\n", deviceIdLen, deviceId, deviceKeyLen, deviceKey);
                sendRoomKeyToDevice(curl, olmSess,
                    "@pscho:matrix.org",
                    deviceId, deviceKey, dId, dKey,
                    roomId, strlen(roomId),
                    sessionId, strlen(sessionId),
                    sessionKey, strlen(sessionKey));
            }
            curlStringDelete(&devicesRes);
        }
        if (command(msg, "send room key")) {
            char deviceId[TMP_LEN];
            char deviceKey[TMP_LEN];
            char roomId[TMP_LEN];
            char sessionId[TMP_LEN];
            char sessionKey[TMP_LEN];
            promptStr("deviceId", deviceId);
            promptStr("deviceKey", deviceKey);
            promptStr("roomId", roomId);
            promptStr("sessionId", sessionId);
            promptStr("sessionKey", sessionKey);

            CurlStr sendRes =
                sendRoomKeyToDevice(curl, olmSess,
                    "@pscho:matrix.org",
                    deviceId, deviceKey, dId, dKey,
                    roomId, strlen(roomId),
                    (char *)sessionId, strlen(sessionId),
                    (char *)sessionKey, strlen(sessionKey));
            prettyPrint(sendRes.str, sendRes.size);
            curlStringDelete(&sendRes);
        }
        if (command(msg, "send megolm")) {
            char roomId[TMP_LEN];
            char msg[TMP_LEN];
            promptStr("roomId", roomId);
            promptStr("msg", msg);

            sendGroupMsg(curl, outboundGroupSess, roomId, msg);
        }
    }

    // store OlmAccount for later
    saveOlmAccount(olmAcc, "olmacc.dat", "abcde", 5);

    puts("done");

    free((void *)olmAcc);

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}