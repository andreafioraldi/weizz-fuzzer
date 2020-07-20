#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "weizz-llvm.h"

#define CALL_SIZE 5

#define RET_CALL_CHAIN (uintptr_t) __builtin_return_address(0)

static inline void weizz_log_rtn(
    uintptr_t pc, uint64_t* Arg1, uint64_t* Arg2, int shape) {
    
  uintptr_t k = (pc >> 4) ^ (pc << 8);
  k &= WMAP_WIDTH - 1; 
  
  heavy_map->headers[k].id = k;
  
  u32 hits = heavy_map->headers[k].hits;
  heavy_map->headers[k].hits = hits + 4;
  if (!heavy_map->headers[k].cnt)
    heavy_map->headers[k].cnt = cmp_counter++;

  heavy_map->headers[k].shape = shape;

  size_t i;
  i = hits & (CMP_MAP_H - 1);
  heavy_map->log[k][i].v0 = Arg1[0];
  heavy_map->log[k][i].v1 = Arg2[0];
  i = (hits +1) & (CMP_MAP_H - 1);
  heavy_map->log[k][i].v0 = Arg1[1];
  heavy_map->log[k][i].v1 = Arg2[1];
  i = (hits +2) & (CMP_MAP_H - 1);
  heavy_map->log[k][i].v0 = Arg1[2];
  heavy_map->log[k][i].v1 = Arg2[2];
  i = (hits +3) & (CMP_MAP_H - 1);
  heavy_map->log[k][i].v0 = Arg1[3];
  heavy_map->log[k][i].v1 = Arg2[3];

  heavy_map->headers[k].type = CMP_TYPE_RTN;

}


static inline int weizz_strcmp(const char* s1, const char* s2, uintptr_t addr) {
    size_t i;
    for (i = 0; s1[i] == s2[i]; i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }
    
    if (i <= STR_LOG_SIZE) {
      char a1[STR_LOG_SIZE];
      char a2[STR_LOG_SIZE];
      __builtin_memcpy(a1, s1, i);
      __builtin_memcpy(a2, s2, i);
      weizz_log_rtn(RET_CALL_CHAIN, (uint64_t*)a1, (uint64_t*)a2, i-1);
    }
    
    return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

static inline int weizz_strcasecmp(const char* s1, const char* s2, uintptr_t addr) {
    size_t i;
    for (i = 0; tolower((unsigned char)s1[i]) == tolower((unsigned char)s2[i]); i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    if (i <= STR_LOG_SIZE) {
      char a1[STR_LOG_SIZE];
      char a2[STR_LOG_SIZE];
      __builtin_memcpy(a1, s1, i);
      __builtin_memcpy(a2, s2, i);
      weizz_log_rtn(RET_CALL_CHAIN, (uint64_t*)a1, (uint64_t*)a2, i-1);
    }

    return (tolower((unsigned char)s1[i]) - tolower((unsigned char)s2[i]));
}

static inline int weizz_strncmp(const char* s1, const char* s2, size_t n, uintptr_t addr) {
    size_t i;
    for (i = 0; i < n; i++) {
        if ((s1[i] != s2[i]) || s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    if (i <= STR_LOG_SIZE) {
      char a1[STR_LOG_SIZE];
      char a2[STR_LOG_SIZE];
      __builtin_memcpy(a1, s1, i);
      __builtin_memcpy(a2, s2, i);
      weizz_log_rtn(RET_CALL_CHAIN, (uint64_t*)a1, (uint64_t*)a2, i-1);
    }

    if (i == n) {
        return 0;
    }
    return (unsigned char)s1[i] - (unsigned char)s2[i];
}

static inline int weizz_strncasecmp(const char* s1, const char* s2, size_t n, uintptr_t addr) {
    size_t i;
    for (i = 0; i < n; i++) {
        if ((tolower((unsigned char)s1[i]) != tolower((unsigned char)s2[i])) || s1[i] == '\0' ||
            s2[i] == '\0') {
            break;
        }
    }

    if (i <= STR_LOG_SIZE) {
      char a1[STR_LOG_SIZE];
      char a2[STR_LOG_SIZE];
      __builtin_memcpy(a1, s1, i);
      __builtin_memcpy(a2, s2, i);
      weizz_log_rtn(RET_CALL_CHAIN, (uint64_t*)a1, (uint64_t*)a2, i-1);
    }

    if (i == n) {
        return 0;
    }
    return tolower((unsigned char)s1[i]) - tolower((unsigned char)s2[i]);
}

static inline char* weizz_strstr(const char* haystack, const char* needle, uintptr_t addr) {
    size_t needle_len = __builtin_strlen(needle);
    if (needle_len == 0) {
        return (char*)haystack;
    }

    // TODO

    const char* h = haystack;
    for (; (h = __builtin_strchr(h, needle[0])) != NULL; h++) {
        if (__builtin_strncmp(h, needle, needle_len) == 0) {
            return (char*)h;
        }
    }
    return NULL;
}

static inline char* weizz_strcasestr(const char* haystack, const char* needle, uintptr_t addr) {
    size_t needle_len = __builtin_strlen(needle);

    // TODO

    for (size_t i = 0; haystack[i]; i++) {
        if (__builtin_strncasecmp(&haystack[i], needle, needle_len) == 0) {
            return (char*)(&haystack[i]);
        }
    }
    return NULL;
}

static inline int weizz_memcmp(const void* m1, const void* m2, size_t n, uintptr_t addr) {
    const unsigned char* s1 = (const unsigned char*)m1;
    const unsigned char* s2 = (const unsigned char*)m2;

    size_t i;
    for (i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            break;
        }
    }

    if (n <= STR_LOG_SIZE) {
      char a1[STR_LOG_SIZE];
      char a2[STR_LOG_SIZE];
      __builtin_memcpy(a1, s1, n);
      __builtin_memcpy(a2, s2, n);
      weizz_log_rtn(RET_CALL_CHAIN, (uint64_t*)a1, (uint64_t*)a2, n-1);
    }

    if (i == n) {
        return 0;
    }
    return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

static inline void* weizz_memmem(const void* haystack, size_t haystacklen, const void* needle,
    size_t needlelen, uintptr_t addr) {
    if (needlelen > haystacklen) {
        return NULL;
    }
    if (needlelen == 0) {
        return (void*)haystack;
    }

    // TODO

    const char* h = haystack;
    for (size_t i = 0; i <= (haystacklen - needlelen); i++) {
        if (__builtin_memcmp(&h[i], needle, needlelen) == 0) {
            return (void*)(&h[i]);
        }
    }
    return NULL;
}

/* Define a weak function x, as well as __wrap_x pointing to x */
#define XSTR(x) #x
#define XVAL(x) x
#define WEAK_WRAP(ret, func, ...) \
    _Pragma(XSTR(weak func = __wrap_##func)) XVAL(ret) XVAL(__wrap_##func)(__VA_ARGS__)

/* Typical libc wrappers */
WEAK_WRAP(int, strcmp, const char* s1, const char* s2) {
    return weizz_strcmp(s1, s2, RET_CALL_CHAIN);
}
WEAK_WRAP(int, strcasecmp, const char* s1, const char* s2) {
    return weizz_strcasecmp(s1, s2, RET_CALL_CHAIN);
}
WEAK_WRAP(int, strncmp, const char* s1, const char* s2, size_t n) {
    return weizz_strncmp(s1, s2, n, RET_CALL_CHAIN);
}
WEAK_WRAP(int, strncasecmp, const char* s1, const char* s2, size_t n) {
    return weizz_strncasecmp(s1, s2, n, RET_CALL_CHAIN);
}
WEAK_WRAP(char*, strstr, const char* haystack, const char* needle) {
    return weizz_strstr(haystack, needle, RET_CALL_CHAIN);
}
WEAK_WRAP(char*, strcasestr, const char* haystack, const char* needle) {
    return weizz_strcasestr(haystack, needle, RET_CALL_CHAIN);
}
WEAK_WRAP(int, memcmp, const void* m1, const void* m2, size_t n) {
    return weizz_memcmp(m1, m2, n, RET_CALL_CHAIN);
}
WEAK_WRAP(int, bcmp, const void* m1, const void* m2, size_t n) {
    return weizz_memcmp(m1, m2, n, RET_CALL_CHAIN);
}
WEAK_WRAP(
    void*, memmem, const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    return weizz_memmem(haystack, haystacklen, needle, needlelen, RET_CALL_CHAIN);
}

/*
 * Apache's httpd wrappers
 */
WEAK_WRAP(int, ap_cstr_casecmp, const char* s1, const char* s2) {
    return weizz_strcasecmp(s1, s2, RET_CALL_CHAIN);
}

WEAK_WRAP(int, ap_cstr_casecmpn, const char* s1, const char* s2, size_t n) {
    return weizz_strncasecmp(s1, s2, n, RET_CALL_CHAIN);
}

WEAK_WRAP(const char*, ap_strcasestr, const char* s1, const char* s2) {
    return weizz_strcasestr(s1, s2, RET_CALL_CHAIN);
}

WEAK_WRAP(int, apr_cstr_casecmp, const char* s1, const char* s2) {
    return weizz_strcasecmp(s1, s2, RET_CALL_CHAIN);
}

WEAK_WRAP(int, apr_cstr_casecmpn, const char* s1, const char* s2, size_t n) {
    return weizz_strncasecmp(s1, s2, n, RET_CALL_CHAIN);
}

/*
 * *SSL wrappers
 */
WEAK_WRAP(int, CRYPTO_memcmp, const void* m1, const void* m2, size_t len) {
    return weizz_memcmp(m1, m2, len, RET_CALL_CHAIN);
}

WEAK_WRAP(int, OPENSSL_memcmp, const void* m1, const void* m2, size_t len) {
    return weizz_memcmp(m1, m2, len, RET_CALL_CHAIN);
}

WEAK_WRAP(int, OPENSSL_strcasecmp, const char* s1, const char* s2) {
    return weizz_strcasecmp(s1, s2, RET_CALL_CHAIN);
}

WEAK_WRAP(int, OPENSSL_strncasecmp, const char* s1, const char* s2, size_t len) {
    return weizz_strncasecmp(s1, s2, len, RET_CALL_CHAIN);
}

WEAK_WRAP(int32_t, memcmpct, const void* s1, const void* s2, size_t len) {
    return weizz_memcmp(s1, s2, len, RET_CALL_CHAIN);
}

/*
 * libXML wrappers
 */
WEAK_WRAP(int, xmlStrncmp, const char* s1, const char* s2, int len) {
    if (len <= 0) {
        return 0;
    }
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return weizz_strncmp(s1, s2, (size_t)len, RET_CALL_CHAIN);
}

WEAK_WRAP(int, xmlStrcmp, const char* s1, const char* s2) {
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return weizz_strcmp(s1, s2, RET_CALL_CHAIN);
}

WEAK_WRAP(int, xmlStrEqual, const char* s1, const char* s2) {
    if (s1 == s2) {
        return 1;
    }
    if (s1 == NULL) {
        return 0;
    }
    if (s2 == NULL) {
        return 0;
    }
    if (weizz_strcmp(s1, s2, RET_CALL_CHAIN) == 0) {
        return 1;
    }
    return 0;
}

WEAK_WRAP(int, xmlStrcasecmp, const char* s1, const char* s2) {
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return weizz_strcasecmp(s1, s2, RET_CALL_CHAIN);
}

WEAK_WRAP(int, xmlStrncasecmp, const char* s1, const char* s2, int len) {
    if (len <= 0) {
        return 0;
    }
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return weizz_strncasecmp(s1, s2, (size_t)len, RET_CALL_CHAIN);
}

WEAK_WRAP(const char*, xmlStrstr, const char* haystack, const char* needle) {
    if (haystack == NULL) {
        return NULL;
    }
    if (needle == NULL) {
        return NULL;
    }
    return weizz_strstr(haystack, needle, RET_CALL_CHAIN);
}

WEAK_WRAP(const char*, xmlStrcasestr, const char* haystack, const char* needle) {
    if (haystack == NULL) {
        return NULL;
    }
    if (needle == NULL) {
        return NULL;
    }
    return weizz_strcasestr(haystack, needle, RET_CALL_CHAIN);
}

/*
 * Samba wrappers
 */
WEAK_WRAP(int, memcmp_const_time, const void* s1, const void* s2, size_t n) {
    return weizz_memcmp(s1, s2, n, RET_CALL_CHAIN);
}

WEAK_WRAP(bool, strcsequal, const void* s1, const void* s2) {
    if (s1 == s2) {
        return true;
    }
    if (!s1 || !s2) {
        return false;
    }
    return (weizz_strcmp(s1, s2, RET_CALL_CHAIN) == 0);
}
