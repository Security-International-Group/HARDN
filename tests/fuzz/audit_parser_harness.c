/* SPDX-License-Identifier: MIT
 *
 * Fuzz / sanitizer-replay harness for the hardn-audit config parsers.
 *
 * The audit engine is ~3.6k lines of hand-written C that parses host config
 * files (PAM, login.defs, journald.conf, /etc/passwd, ...). Malformed or
 * adversarial input (a tampered file, an over-long line, embedded NULs) is
 * exactly what a memory-safety bug would hide behind, and the normal run
 * never exercises that. This harness drives the parser entry points on
 * arbitrary bytes.
 *
 * Dual mode:
 *   - libFuzzer: build with `clang -fsanitize=fuzzer,address,undefined`.
 *     libFuzzer supplies main() and calls LLVMFuzzerTestOneInput.
 *   - Standalone replay: build with `cc -fsanitize=address,undefined` and
 *     pass corpus files as argv. Portable to any CI with a C compiler; no
 *     libFuzzer runtime required.
 */

#define HARDN_NO_MAIN
#include "../../src/audit/hardn_audit.c"

#include <stdint.h>
#include <unistd.h>

/* Exercise the parser surfaces on one input buffer. */
static void run_one(const uint8_t *data, size_t size) {
    char *s = (char *)malloc(size + 1);
    if (!s) return;
    if (size) memcpy(s, data, size);
    s[size] = '\0';

    /* 1) parse_pwquality_line on the raw bytes, and again with a
     * pam_pwquality.so prefix so the tokenizer path is reached. */
    pam_pwquality_config_t cfg;
    init_pwquality_config(&cfg);
    parse_pwquality_line(&cfg, s);

    size_t plen = size + 20;
    char *prefixed = (char *)malloc(plen);
    if (prefixed) {
        snprintf(prefixed, plen, "pam_pwquality.so %s", s);
        init_pwquality_config(&cfg);
        parse_pwquality_line(&cfg, prefixed);
        free(prefixed);
    }

    /* 2) file-backed parsers via a temp file holding the raw bytes. */
    char tmpl[] = "/tmp/hardn-fuzz-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0) {
        ssize_t w = write(fd, data, size);
        close(fd);
        if (w >= 0) {
            char **lines = NULL;
            size_t count = 0;
            if (load_file_lines(tmpl, &lines, &count) == 0) {
                free_lines(lines, count);
            }
            /* read_keyvalue_from_file into both a normal and a deliberately
             * tiny output buffer, to stress the bounded copy. */
            char out[64];
            read_keyvalue_from_file(tmpl, "Compress", out, sizeof(out));
            char tiny[4];
            read_keyvalue_from_file(tmpl, "Storage", tiny, sizeof(tiny));
        }
        unlink(tmpl);
    }

    free(s);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    run_one(data, size);
    return 0;
}

/* libFuzzer defines this macro and supplies its own main(); only compile the
 * standalone replay driver when it is absent. */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <stdio.h>

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        if (fseek(f, 0, SEEK_END) != 0) {
            fclose(f);
            continue;
        }
        long n = ftell(f);
        if (n < 0) {
            fclose(f);
            continue;
        }
        rewind(f);
        uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
        if (buf) {
            size_t r = fread(buf, 1, (size_t)n, f);
            run_one(buf, r);
            free(buf);
        }
        fclose(f);
    }
    return 0;
}
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
