/* Benchmark DLL source for the AI Assembly Explainer.
 *
 * Small functions of increasing difficulty, each with known behaviour, so the
 * C source is the answer key for every explanation the model produces. Compile
 * into four variants (-O0/-O2, with/without symbols) with build.sh and grade
 * the explanations against the comments here.
 *
 * Analyse only DLLs you compiled yourself -- these are exactly that.
 */
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

/* 1. Sum an array of ints. */
EXPORT int sum_array(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}

/* 2. Reverse a string in place. */
EXPORT void str_reverse(char *s) {
    size_t i = 0, j = strlen(s);
    if (j == 0) return;
    for (j--; i < j; i++, j--) { char t = s[i]; s[i] = s[j]; s[j] = t; }
}

/* 3. Compare two strings; return 0 if equal. */
EXPORT int str_compare(const char *a, const char *b) {
    while (*a && (*a == *b)) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

/* 4. Fletcher-16 checksum. */
EXPORT uint16_t checksum16(const uint8_t *data, size_t len) {
    uint16_t sum1 = 0, sum2 = 0;
    for (size_t i = 0; i < len; i++) {
        sum1 = (sum1 + data[i]) % 255;
        sum2 = (sum2 + sum1) % 255;
    }
    return (sum2 << 8) | sum1;
}

/* 5. XOR cipher with a repeating key (symmetric). */
EXPORT void xor_cipher(uint8_t *buf, size_t len, const uint8_t *key, size_t klen) {
    for (size_t i = 0; i < len; i++) buf[i] ^= key[i % klen];
}

/* 6. Switch-based state machine: classify a byte. */
EXPORT int classify(int c) {
    switch (c) {
        case '\n': case '\t': case ' ': return 1;   /* whitespace */
        case '+': case '-': case '*': case '/': return 2; /* operator */
        default: return (c >= '0' && c <= '9') ? 3 : 0;    /* digit / other */
    }
}

/* 7. Linked-list search. */
struct node { int key; struct node *next; };
EXPORT struct node *list_find(struct node *head, int key) {
    for (; head; head = head->next) if (head->key == key) return head;
    return 0;
}

/* 8. Recursive factorial. */
EXPORT uint64_t factorial(uint32_t n) {
    return n <= 1 ? 1 : (uint64_t)n * factorial(n - 1);
}

#ifdef _WIN32
/* 9. Calls a Windows API: writes a byte count to a registry value. Planted
 *    behaviour for the agent benchmark ("does this touch the registry?"). */
EXPORT LONG write_count(DWORD count) {
    HKEY key;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\AIExplainerTest",
                              0, NULL, 0, KEY_WRITE, NULL, &key, NULL);
    if (rc != ERROR_SUCCESS) return rc;
    rc = RegSetValueExW(key, L"Count", 0, REG_DWORD,
                        (const BYTE *)&count, sizeof(count));
    RegCloseKey(key);
    return rc;
}
#endif
