#define _POSIX_C_SOURCE 200809L

/// This file is an openscap based compliance module for internal auditing 


#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_EVIDENCE_LEN 512

typedef enum {
    RULE_STATUS_PASS,
    RULE_STATUS_FAIL,
    RULE_STATUS_NOT_APPLICABLE,
    RULE_STATUS_ERROR,
    RULE_STATUS_NOT_IMPLEMENTED
} rule_status_t;

typedef struct {
    rule_status_t status;
    char evidence[MAX_EVIDENCE_LEN];
} rule_result_t;

struct rule_definition;
typedef rule_result_t (*rule_check_fn)(const struct rule_definition *rule);

typedef struct rule_definition {
    const char *id;
    const char *title;
    const char *category;
    const char *severity;
    rule_check_fn check;
} rule_definition_t;

static const char *status_to_string(rule_status_t status) {
    switch (status) {
        case RULE_STATUS_PASS:
            return "pass";
        case RULE_STATUS_FAIL:
            return "fail";
        case RULE_STATUS_NOT_APPLICABLE:
            return "not_applicable";
        case RULE_STATUS_ERROR:
            return "error";
        case RULE_STATUS_NOT_IMPLEMENTED:
        default:
            return "not_implemented";
    }
}

static void json_escape_and_print(FILE *out, const char *input) {
    fputc('"', out);
    for (const unsigned char *ptr = (const unsigned char *)input; *ptr; ++ptr) {
        unsigned char c = *ptr;
        switch (c) {
            case '\\':
                fputs("\\\\", out);
                break;
            case '\"':
                fputs("\\\"", out);
                break;
            case '\b':
                fputs("\\b", out);
                break;
            case '\f':
                fputs("\\f", out);
                break;
            case '\n':
                fputs("\\n", out);
                break;
            case '\r':
                fputs("\\r", out);
                break;
            case '\t':
                fputs("\\t", out);
                break;
            default:
                if (c < 0x20) {
                    fprintf(out, "\\u%04x", c);
                } else {
                    fputc(c, out);
                }
                break;
        }
    }
    fputc('"', out);
}

static rule_result_t check_not_implemented(const rule_definition_t *rule) {
    (void)rule;
    rule_result_t result = { RULE_STATUS_NOT_IMPLEMENTED, "" };
    snprintf(result.evidence, sizeof(result.evidence), "check not yet implemented");
    return result;
}

static rule_result_t check_error(const char *message) {
    rule_result_t result = { RULE_STATUS_ERROR, "" };
    if (message) {
        snprintf(result.evidence, sizeof(result.evidence), "%s", message);
    }
    return result;
}

static int load_file_lines(const char *path, char ***lines_out, size_t *count_out) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    size_t capacity = 64;
    size_t count = 0;
    char **lines = calloc(capacity, sizeof(char *));
    if (!lines) {
        fclose(fp);
        return -1;
    }

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        while (len > 0 && (buffer[len - 1] == '\n' || buffer[len - 1] == '\r')) {
            buffer[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }
        if (count == capacity) {
            capacity *= 2;
            char **tmp = realloc(lines, capacity * sizeof(char *));
            if (!tmp) {
                fclose(fp);
                for (size_t i = 0; i < count; ++i) {
                    free(lines[i]);
                }
                free(lines);
                return -1;
            }
            lines = tmp;
        }
        lines[count] = strdup(buffer);
        if (!lines[count]) {
            fclose(fp);
            for (size_t i = 0; i < count; ++i) {
                free(lines[i]);
            }
            free(lines);
            return -1;
        }
        count++;
    }

    fclose(fp);
    *lines_out = lines;
    *count_out = count;
    return 0;
}

static void free_lines(char **lines, size_t count) {
    if (!lines) return;
    for (size_t i = 0; i < count; ++i) {
        free(lines[i]);
    }
    free(lines);
}

//////// Helper parsing for PAM pwquality 

typedef struct {
    bool found;
    long minlen;
    long dcredit;
    long ucredit;
    long lcredit;
    long ocredit;
    long minclass;
    long retry;
} pam_pwquality_config_t;

static void init_pwquality_config(pam_pwquality_config_t *cfg) {
    cfg->found = false;
    cfg->minlen = LONG_MIN;
    cfg->dcredit = LONG_MIN;
    cfg->ucredit = LONG_MIN;
    cfg->lcredit = LONG_MIN;
    cfg->ocredit = LONG_MIN;
    cfg->minclass = LONG_MIN;
    cfg->retry = LONG_MIN;
}

static void apply_pwquality_option(pam_pwquality_config_t *cfg, const char *key, const char *value) {
    if (!key || !value) return;
    long parsed = strtol(value, NULL, 10);
    if (strcmp(key, "minlen") == 0) cfg->minlen = parsed;
    else if (strcmp(key, "dcredit") == 0) cfg->dcredit = parsed;
    else if (strcmp(key, "ucredit") == 0) cfg->ucredit = parsed;
    else if (strcmp(key, "lcredit") == 0) cfg->lcredit = parsed;
    else if (strcmp(key, "ocredit") == 0) cfg->ocredit = parsed;
    else if (strcmp(key, "minclass") == 0) cfg->minclass = parsed;
    else if (strcmp(key, "retry") == 0) cfg->retry = parsed;
}

static void parse_pwquality_line(pam_pwquality_config_t *cfg, const char *line) {
    if (!line) return;
    if (strstr(line, "pam_pwquality.so") == NULL && strstr(line, "pam_cracklib.so") == NULL) {
        return;
    }
    cfg->found = true;

    char *dup = strdup(line);
    if (!dup) return;
    char *token = strtok(dup, " \\t");
    while (token) {
        char *eq = strchr(token, '=');
        if (eq) {
            *eq = '\0';
            const char *key = token;
            const char *value = eq + 1;
            apply_pwquality_option(cfg, key, value);
        }
        token = strtok(NULL, " \\t");
    }
    free(dup);
}

static void load_pwquality_config(pam_pwquality_config_t *cfg) {
    static bool loaded = false;
    static pam_pwquality_config_t cached;

    if (loaded) {
        *cfg = cached;
        return;
    }

    pam_pwquality_config_t local;
    init_pwquality_config(&local);

    const char *pam_paths[] = {
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        NULL
    };

    for (size_t i = 0; pam_paths[i]; ++i) {
        char **lines = NULL;
        size_t count = 0;
        if (load_file_lines(pam_paths[i], &lines, &count) == 0) {
            for (size_t j = 0; j < count; ++j) {
                parse_pwquality_line(&local, lines[j]);
            }
        }
        free_lines(lines, count);
        if (local.found) {
            break;
        }
    }

    ///////////////// Also parse /etc/security/pwquality.conf for overrides */
    char **conf_lines = NULL;
    size_t conf_count = 0;
    if (load_file_lines("/etc/security/pwquality.conf", &conf_lines, &conf_count) == 0) {
        for (size_t i = 0; i < conf_count; ++i) {
            char *line = conf_lines[i];
            while (isspace((unsigned char)*line)) line++;
            if (*line == '#' || *line == '\0') continue;
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            char *key = line;
            char *value = eq + 1;
            while (key && *key && isspace((unsigned char)*key)) key++;
            char *end = key + strlen(key);
            while (end > key && isspace((unsigned char)end[-1])) end--;
            *end = '\0';
            while (*value && isspace((unsigned char)*value)) value++;
            end = value + strlen(value);
            while (end > value && isspace((unsigned char)end[-1])) end--;
            *end = '\0';
            apply_pwquality_option(&local, key, value);
        }
    }
    free_lines(conf_lines, conf_count);

    cached = local;
    loaded = true;
    *cfg = cached;
}

///////////////Specific rule checks (initial subset) ---------- */

static rule_result_t check_accounts_password_pam_minlen(const rule_definition_t *rule) {
    (void)rule;
    pam_pwquality_config_t cfg;
    load_pwquality_config(&cfg);
    if (!cfg.found && cfg.minlen == LONG_MIN) {
        return check_error("pam_pwquality not configured (common-password)");
    }
    long minlen = (cfg.minlen == LONG_MIN) ? 0 : cfg.minlen;
    if (minlen >= 14) {
        rule_result_t result = { RULE_STATUS_PASS, "" };
        snprintf(result.evidence, sizeof(result.evidence), "minlen=%ld", minlen);
        return result;
    }
    rule_result_t result = { RULE_STATUS_FAIL, "" };
    snprintf(result.evidence, sizeof(result.evidence), "minlen=%ld (expected >=14)", minlen);
    return result;
}

static rule_result_t check_accounts_password_pam_retry(const rule_definition_t *rule) {
    (void)rule;
    pam_pwquality_config_t cfg;
    load_pwquality_config(&cfg);
    if (!cfg.found && cfg.retry == LONG_MIN) {
        return check_error("pam_pwquality not configured (retry)");
    }
    long retry = (cfg.retry == LONG_MIN) ? 0 : cfg.retry;
    if (retry > 0 && retry <= 3) {
        rule_result_t result = { RULE_STATUS_PASS, "" };
        snprintf(result.evidence, sizeof(result.evidence), "retry=%ld", retry);
        return result;
    }
    rule_result_t result = { RULE_STATUS_FAIL, "" };
    snprintf(result.evidence, sizeof(result.evidence), "retry=%ld (expected 1-3)", retry);
    return result;
}

static rule_result_t check_pam_credit(const rule_definition_t *rule, long value, const char *key) {
    (void)rule;
    if (value == LONG_MIN) {
        return check_error("parameter missing");
    }
    if (value <= -1) {
        rule_result_t result = { RULE_STATUS_PASS, "" };
        snprintf(result.evidence, sizeof(result.evidence), "%s=%ld", key, value);
        return result;
    }
    rule_result_t result = { RULE_STATUS_FAIL, "" };
    snprintf(result.evidence, sizeof(result.evidence), "%s=%ld (expected <= -1)", key, value);
    return result;
}

static rule_result_t check_accounts_password_pam_dcredit(const rule_definition_t *rule) {
    pam_pwquality_config_t cfg;
    load_pwquality_config(&cfg);
    if (!cfg.found && cfg.dcredit == LONG_MIN) {
        return check_error("pam_pwquality not configured (dcredit)");
    }
    return check_pam_credit(rule, cfg.dcredit, "dcredit");
}

static rule_result_t check_accounts_password_pam_ucredit(const rule_definition_t *rule) {
    pam_pwquality_config_t cfg;
    load_pwquality_config(&cfg);
    if (!cfg.found && cfg.ucredit == LONG_MIN) {
        return check_error("pam_pwquality not configured (ucredit)");
    }
    return check_pam_credit(rule, cfg.ucredit, "ucredit");
}

static rule_result_t check_accounts_password_pam_lcredit(const rule_definition_t *rule) {
    pam_pwquality_config_t cfg;
    load_pwquality_config(&cfg);
    if (!cfg.found && cfg.lcredit == LONG_MIN) {
        return check_error("pam_pwquality not configured (lcredit)");
    }
    return check_pam_credit(rule, cfg.lcredit, "lcredit");
}

static rule_result_t check_accounts_password_pam_ocredit(const rule_definition_t *rule) {
    pam_pwquality_config_t cfg;
    load_pwquality_config(&cfg);
    if (!cfg.found && cfg.ocredit == LONG_MIN) {
        return check_error("pam_pwquality not configured (ocredit)");
    }
    return check_pam_credit(rule, cfg.ocredit, "ocredit");
}

static rule_result_t check_accounts_password_pam_minclass(const rule_definition_t *rule) {
    (void)rule;
    pam_pwquality_config_t cfg;
    load_pwquality_config(&cfg);
    long minclass = (cfg.minclass == LONG_MIN) ? 0 : cfg.minclass;
    if (minclass >= 4) {
        rule_result_t result = { RULE_STATUS_PASS, "" };
        snprintf(result.evidence, sizeof(result.evidence), "minclass=%ld", minclass);
        return result;
    }
    rule_result_t result = { RULE_STATUS_FAIL, "" };
    snprintf(result.evidence, sizeof(result.evidence), "minclass=%ld (expected >=4)", minclass);
    return result;
}

static rule_result_t check_set_password_hashing_algorithm_logindefs(const rule_definition_t *rule) {
    (void)rule;
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines("/etc/login.defs", &lines, &count) != 0) {
        return check_error("unable to read /etc/login.defs");
    }

    char method[64] = "";
    for (size_t i = 0; i < count; ++i) {
        char *line = lines[i];
        while (isspace((unsigned char)*line)) line++;
        if (*line == '#' || *line == '\0') continue;
        if (strncasecmp(line, "ENCRYPT_METHOD", strlen("ENCRYPT_METHOD")) == 0) {
            char *value = line + strlen("ENCRYPT_METHOD");
            while (*value && isspace((unsigned char)*value)) value++;
            snprintf(method, sizeof(method), "%s", value);
            break;
        }
    }
    free_lines(lines, count);

    if (method[0] == '\0') {
        return check_error("ENCRYPT_METHOD not defined");
    }

    if (strcasecmp(method, "SHA512") == 0) {
        rule_result_t result = { RULE_STATUS_PASS, "" };
        snprintf(result.evidence, sizeof(result.evidence), "ENCRYPT_METHOD=%s", method);
        return result;
    }

    rule_result_t result = { RULE_STATUS_FAIL, "" };
    snprintf(result.evidence, sizeof(result.evidence), "ENCRYPT_METHOD=%s (expected SHA512)", method);
    return result;
}

static rule_result_t check_accounts_password_all_shadowed(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) {
        return check_error("unable to open /etc/passwd");
    }

    char line[4096];
    int issues = 0;
    char offending[128] = "";

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        char *saveptr = NULL;
        char *user = strtok_r(line, ":", &saveptr);
        char *pass = strtok_r(NULL, ":", &saveptr);
        if (!user || !pass) continue;
        if (pass[0] == 'x' && pass[1] == '\0') continue;
        if (pass[0] == '!' || pass[0] == '*') continue;
        if (strstr(pass, "$")) {
            issues++;
            snprintf(offending, sizeof(offending), "%s", user);
            break;
        }
    }

    fclose(fp);

    if (issues == 0) {
        rule_result_t result = { RULE_STATUS_PASS, "" };
        snprintf(result.evidence, sizeof(result.evidence), "all passwd entries shadowed");
        return result;
    }

    rule_result_t result = { RULE_STATUS_FAIL, "" };
    snprintf(result.evidence, sizeof(result.evidence), "account '%s' stores password in /etc/passwd", offending);
    return result;
}

static int compare_uid(const void *a, const void *b) {
    uid_t ua = *(const uid_t *)a;
    uid_t ub = *(const uid_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static rule_result_t check_account_unique_id(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) {
        return check_error("unable to open /etc/passwd");
    }

    size_t capacity = 128;
    size_t count = 0;
    uid_t *uids = malloc(capacity * sizeof(uid_t));
    if (!uids) {
        fclose(fp);
        return check_error("memory allocation failed");
    }

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *saveptr = NULL;
        strtok_r(line, ":", &saveptr); /* username */
        strtok_r(NULL, ":", &saveptr); /* password */
        char *uid_str = strtok_r(NULL, ":", &saveptr);
        if (!uid_str) continue;
        long uid_val = strtol(uid_str, NULL, 10);
        if (uid_val < 0) continue;
        if (count == capacity) {
            capacity *= 2;
            uid_t *tmp = realloc(uids, capacity * sizeof(uid_t));
            if (!tmp) {
                free(uids);
                fclose(fp);
                return check_error("memory allocation failed");
            }
            uids = tmp;
        }
        uids[count++] = (uid_t)uid_val;
    }
    fclose(fp);

    if (count == 0) {
        free(uids);
        rule_result_t result = { RULE_STATUS_NOT_APPLICABLE, "" };
        snprintf(result.evidence, sizeof(result.evidence), "no local accounts found");
        return result;
    }

    qsort(uids, count, sizeof(uid_t), compare_uid);
    for (size_t i = 1; i < count; ++i) {
        if (uids[i] == uids[i - 1]) {
            rule_result_t result = { RULE_STATUS_FAIL, "" };
            snprintf(result.evidence, sizeof(result.evidence), "duplicate UID %u detected", uids[i]);
            free(uids);
            return result;
        }
    }

    free(uids);
    rule_result_t result = { RULE_STATUS_PASS, "" };
    snprintf(result.evidence, sizeof(result.evidence), "no duplicate UIDs");
    return result;
}

static rule_result_t check_account_unique_name(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) {
        return check_error("unable to open /etc/passwd");
    }

    size_t capacity = 128;
    size_t count = 0;
    char **names = calloc(capacity, sizeof(char *));
    if (!names) {
        fclose(fp);
        return check_error("memory allocation failed");
    }

    char line[4096];
    bool duplicate = false;
    char offending[128] = "";

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *saveptr = NULL;
        char *user = strtok_r(line, ":", &saveptr);
        if (!user) continue;
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(names[i], user) == 0) {
                duplicate = true;
                snprintf(offending, sizeof(offending), "%s", user);
                break;
            }
        }
        if (duplicate) break;
        if (count == capacity) {
            capacity *= 2;
            char **tmp = realloc(names, capacity * sizeof(char *));
            if (!tmp) {
                fclose(fp);
                for (size_t i = 0; i < count; ++i) free(names[i]);
                free(names);
                return check_error("memory allocation failed");
            }
            names = tmp;
        }
        names[count] = strdup(user);
        if (!names[count]) {
            fclose(fp);
            for (size_t i = 0; i < count; ++i) free(names[i]);
            free(names);
            return check_error("memory allocation failed");
        }
        count++;
    }
    fclose(fp);

    for (size_t i = 0; i < count; ++i) free(names[i]);
    free(names);

    if (duplicate) {
        rule_result_t result = { RULE_STATUS_FAIL, "" };
        snprintf(result.evidence, sizeof(result.evidence), "duplicate username '%s'", offending);
        return result;
    }

    rule_result_t result = { RULE_STATUS_PASS, "" };
    snprintf(result.evidence, sizeof(result.evidence), "all usernames unique");
    return result;
}

static int compare_gid(const void *a, const void *b) {
    gid_t ga = *(const gid_t *)a;
    gid_t gb = *(const gid_t *)b;
    if (ga < gb) return -1;
    if (ga > gb) return 1;
    return 0;
}

static rule_result_t check_group_unique_id(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/group", "r");
    if (!fp) {
        return check_error("unable to open /etc/group");
    }

    size_t capacity = 128;
    size_t count = 0;
    gid_t *gids = malloc(capacity * sizeof(gid_t));
    if (!gids) {
        fclose(fp);
        return check_error("memory allocation failed");
    }

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *saveptr = NULL;
        strtok_r(line, ":", &saveptr); /* group name */
        strtok_r(NULL, ":", &saveptr); /* password */
        char *gid_str = strtok_r(NULL, ":", &saveptr);
        if (!gid_str) continue;
        long gid_val = strtol(gid_str, NULL, 10);
        if (gid_val < 0) continue;
        if (count == capacity) {
            capacity *= 2;
            gid_t *tmp = realloc(gids, capacity * sizeof(gid_t));
            if (!tmp) {
                free(gids);
                fclose(fp);
                return check_error("memory allocation failed");
            }
            gids = tmp;
        }
        gids[count++] = (gid_t)gid_val;
    }
    fclose(fp);

    if (count == 0) {
        free(gids);
        rule_result_t result = { RULE_STATUS_NOT_APPLICABLE, "" };
        snprintf(result.evidence, sizeof(result.evidence), "no groups found");
        return result;
    }

    qsort(gids, count, sizeof(gid_t), compare_gid);
    for (size_t i = 1; i < count; ++i) {
        if (gids[i] == gids[i - 1]) {
            rule_result_t result = { RULE_STATUS_FAIL, "" };
            snprintf(result.evidence, sizeof(result.evidence), "duplicate GID %u detected", gids[i]);
            free(gids);
            return result;
        }
    }

    free(gids);
    rule_result_t result = { RULE_STATUS_PASS, "" };
    snprintf(result.evidence, sizeof(result.evidence), "no duplicate GIDs");
    return result;
}

static rule_result_t check_group_unique_name(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/group", "r");
    if (!fp) {
        return check_error("unable to open /etc/group");
    }

    size_t capacity = 128;
    size_t count = 0;
    char **names = calloc(capacity, sizeof(char *));
    if (!names) {
        fclose(fp);
        return check_error("memory allocation failed");
    }

    bool duplicate = false;
    char offending[128] = "";
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *saveptr = NULL;
        char *name = strtok_r(line, ":", &saveptr);
        if (!name) continue;
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(names[i], name) == 0) {
                duplicate = true;
                snprintf(offending, sizeof(offending), "%s", name);
                break;
            }
        }
        if (duplicate) break;
        if (count == capacity) {
            capacity *= 2;
            char **tmp = realloc(names, capacity * sizeof(char *));
            if (!tmp) {
                fclose(fp);
                for (size_t i = 0; i < count; ++i) free(names[i]);
                free(names);
                return check_error("memory allocation failed");
            }
            names = tmp;
        }
        names[count] = strdup(name);
        if (!names[count]) {
            fclose(fp);
            for (size_t i = 0; i < count; ++i) free(names[i]);
            free(names);
            return check_error("memory allocation failed");
        }
        count++;
    }
    fclose(fp);

    for (size_t i = 0; i < count; ++i) free(names[i]);
    free(names);

    if (duplicate) {
        rule_result_t result = { RULE_STATUS_FAIL, "" };
        snprintf(result.evidence, sizeof(result.evidence), "duplicate group name '%s'", offending);
        return result;
    }

    rule_result_t result = { RULE_STATUS_PASS, "" };
    snprintf(result.evidence, sizeof(result.evidence), "all group names unique");
    return result;
}

static rule_result_t check_ensure_shadow_group_empty(const rule_definition_t *rule) {
    (void)rule;
    struct group *grp = getgrnam("shadow");
    if (!grp) {
        rule_result_t result = { RULE_STATUS_NOT_APPLICABLE, "" };
        snprintf(result.evidence, sizeof(result.evidence), "shadow group not present");
        return result;
    }
    if (!grp->gr_mem || !grp->gr_mem[0]) {
        rule_result_t result = { RULE_STATUS_PASS, "" };
        snprintf(result.evidence, sizeof(result.evidence), "shadow group has no members");
        return result;
    }
    rule_result_t result = { RULE_STATUS_FAIL, "" };
    snprintf(result.evidence, sizeof(result.evidence), "shadow group members detected (e.g. %s)", grp->gr_mem[0]);
    return result;
}

////////////// Rule table 

#define RULE_DEF(ID, TITLE, CATEGORY, SEVERITY, CHECK) \
    { (ID), (TITLE), (CATEGORY), (SEVERITY), (CHECK) }

static rule_definition_t RULES[] = {
#include "rules_autogen.inc"
};

#undef RULE_DEF

static void patch_rule_check(const char *id, rule_check_fn fn) {
    size_t total = sizeof(RULES) / sizeof(RULES[0]);
    for (size_t i = 0; i < total; ++i) {
        if (strcmp(RULES[i].id, id) == 0) {
            RULES[i].check = fn;
            return;
        }
    }
}

static void initialize_rule_overrides(void) {
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen", check_accounts_password_pam_minlen);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_pam_retry", check_accounts_password_pam_retry);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_pam_dcredit", check_accounts_password_pam_dcredit);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_pam_ucredit", check_accounts_password_pam_ucredit);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_pam_lcredit", check_accounts_password_pam_lcredit);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_pam_ocredit", check_accounts_password_pam_ocredit);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass", check_accounts_password_pam_minclass);
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_logindefs", check_set_password_hashing_algorithm_logindefs);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed", check_accounts_password_all_shadowed);
    patch_rule_check("xccdf_org.ssgproject.content_rule_account_unique_id", check_account_unique_id);
    patch_rule_check("xccdf_org.ssgproject.content_rule_account_unique_name", check_account_unique_name);
    patch_rule_check("xccdf_org.ssgproject.content_rule_group_unique_id", check_group_unique_id);
    patch_rule_check("xccdf_org.ssgproject.content_rule_group_unique_name", check_group_unique_name);
    patch_rule_check("xccdf_org.ssgproject.content_rule_ensure_shadow_group_empty", check_ensure_shadow_group_empty);
}

int main(void) {
    initialize_rule_overrides();

    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    printf("{\n");
    printf("  \"report_version\": \"1.0\",\n");
    printf("  \"generated_at\": ");
    json_escape_and_print(stdout, timestamp);
    printf(",\n  \"rules\": [\n");

    size_t total = sizeof(RULES) / sizeof(RULES[0]);
    for (size_t i = 0; i < total; ++i) {
        rule_definition_t *rule = &RULES[i];
        rule_result_t result = rule->check(rule);
        printf("    {\n");
        printf("      \"id\": ");
        json_escape_and_print(stdout, rule->id);
        printf(",\n      \"title\": ");
        json_escape_and_print(stdout, rule->title);
        printf(",\n      \"category\": ");
        json_escape_and_print(stdout, rule->category);
        printf(",\n      \"severity\": ");
        json_escape_and_print(stdout, rule->severity);
        printf(",\n      \"status\": ");
        json_escape_and_print(stdout, status_to_string(result.status));
        printf(",\n      \"evidence\": ");
        json_escape_and_print(stdout, result.evidence);
        printf("\n    }");
        if (i + 1 < total) {
            printf(",\n");
        } else {
            printf("\n");
        }
    }

    printf("  ]\n}\n");
    return 0;
}
