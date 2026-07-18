#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* payloadArgs can be NULL if no args needed */
int RunLoaderMode(const char* url, const char* passphrase, const char* payloadArgs);

#ifdef __cplusplus
}
#endif
