#pragma once
static __attribute__((constructor)) void ASYNCTLS_VERSION()
{
    extern const char *asynctls_version_tag;
    if (!*asynctls_version_tag)
        asynctls_version_tag++;
}
