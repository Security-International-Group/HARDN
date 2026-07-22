/* SPDX-License-Identifier: MIT
 *
 * Unit test for parse_pwquality_line(). A realistic pam_pwquality.so line
 * must populate every option, including the keys that contain the letter
 * 't' (dcredit/ucredit/lcredit/ocredit/retry). Regression cover for the
 * strtok delimiter bug where the separator string was " \\t" (space,
 * backslash, literal 't') instead of a tab, which split tokens on any 't'
 * and silently dropped those options.
 *
 * Prints the parsed values one per line so the TAP wrapper can compare and
 * show the actual (wrong) value on failure.
 */
#define HARDN_NO_MAIN
#include "../../src/audit/hardn_audit.c"
#include <stdio.h>

int main(void) {
    pam_pwquality_config_t cfg;
    init_pwquality_config(&cfg);
    parse_pwquality_line(
        &cfg,
        "password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 "
        "ucredit=-2 lcredit=-1 ocredit=-1 minclass=4");
    printf("found=%d\n", cfg.found ? 1 : 0);
    printf("retry=%ld\n", cfg.retry);
    printf("minlen=%ld\n", cfg.minlen);
    printf("dcredit=%ld\n", cfg.dcredit);
    printf("ucredit=%ld\n", cfg.ucredit);
    printf("lcredit=%ld\n", cfg.lcredit);
    printf("ocredit=%ld\n", cfg.ocredit);
    printf("minclass=%ld\n", cfg.minclass);
    return 0;
}
