#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

/// This file is an openscap based compliance module for internal auditing 


#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <stdarg.h>
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

/* ---------- File ownership / permission helpers ---------- */

static rule_result_t pass_evidence(const char *fmt, ...) {
    rule_result_t r = { RULE_STATUS_PASS, "" };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r.evidence, sizeof(r.evidence), fmt, ap);
    va_end(ap);
    return r;
}

static rule_result_t fail_evidence(const char *fmt, ...) {
    rule_result_t r = { RULE_STATUS_FAIL, "" };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r.evidence, sizeof(r.evidence), fmt, ap);
    va_end(ap);
    return r;
}

static rule_result_t na_evidence(const char *fmt, ...) {
    rule_result_t r = { RULE_STATUS_NOT_APPLICABLE, "" };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r.evidence, sizeof(r.evidence), fmt, ap);
    va_end(ap);
    return r;
}

static rule_result_t check_file_owner_named(const char *path, const char *expected_user) {
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT) {
            return na_evidence("%s does not exist", path);
        }
        return check_error("unable to stat path");
    }
    struct passwd *pw = getpwuid(st.st_uid);
    const char *actual = pw ? pw->pw_name : NULL;
    if (actual && strcmp(actual, expected_user) == 0) {
        return pass_evidence("%s owner=%s", path, actual);
    }
    if (actual) {
        return fail_evidence("%s owner=%s (expected %s)", path, actual, expected_user);
    }
    return fail_evidence("%s owner uid=%u (expected %s)", path, (unsigned)st.st_uid, expected_user);
}

static rule_result_t check_file_group_named(const char *path, const char *expected_group) {
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT) {
            return na_evidence("%s does not exist", path);
        }
        return check_error("unable to stat path");
    }
    struct group *gr = getgrgid(st.st_gid);
    const char *actual = gr ? gr->gr_name : NULL;
    if (actual && strcmp(actual, expected_group) == 0) {
        return pass_evidence("%s group=%s", path, actual);
    }
    if (actual) {
        return fail_evidence("%s group=%s (expected %s)", path, actual, expected_group);
    }
    return fail_evidence("%s gid=%u (expected %s)", path, (unsigned)st.st_gid, expected_group);
}

static rule_result_t check_file_mode_max(const char *path, mode_t max_mode) {
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT) {
            return na_evidence("%s does not exist", path);
        }
        return check_error("unable to stat path");
    }
    mode_t actual = st.st_mode & 07777;
    if ((actual & ~max_mode) == 0) {
        return pass_evidence("%s mode=%04o (<= %04o)", path, actual, max_mode);
    }
    return fail_evidence("%s mode=%04o (expected <= %04o)", path, actual, max_mode);
}

#define DEF_FILE_OWNER(name, path, owner) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_file_owner_named(path, owner); \
}

#define DEF_FILE_GROUP(name, path, grp) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_file_group_named(path, grp); \
}

#define DEF_FILE_MODE(name, path, max_mode) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_file_mode_max(path, (mode_t)(max_mode)); \
}

/* Owner = root for the password / shadow / group files and their backups */
DEF_FILE_OWNER(file_owner_etc_passwd,           "/etc/passwd",   "root")
DEF_FILE_OWNER(file_owner_etc_group,            "/etc/group",    "root")
DEF_FILE_OWNER(file_owner_etc_shadow,           "/etc/shadow",   "root")
DEF_FILE_OWNER(file_owner_etc_gshadow,          "/etc/gshadow",  "root")
DEF_FILE_OWNER(file_owner_backup_etc_passwd,    "/etc/passwd-",  "root")
DEF_FILE_OWNER(file_owner_backup_etc_group,     "/etc/group-",   "root")
DEF_FILE_OWNER(file_owner_backup_etc_shadow,    "/etc/shadow-",  "root")
DEF_FILE_OWNER(file_owner_backup_etc_gshadow,   "/etc/gshadow-", "root")

/* Group ownership: Debian convention keeps shadow/gshadow group-owned by `shadow`;
   the SCAP rule expects `root` group ownership which matches RHEL/STIG. We follow
   the SCAP rule expectation; Debian deployments may legitimately fail this. */
DEF_FILE_GROUP(file_groupowner_etc_passwd,         "/etc/passwd",   "root")
DEF_FILE_GROUP(file_groupowner_etc_group,          "/etc/group",    "root")
DEF_FILE_GROUP(file_groupowner_etc_shadow,         "/etc/shadow",   "root")
DEF_FILE_GROUP(file_groupowner_etc_gshadow,        "/etc/gshadow",  "root")
DEF_FILE_GROUP(file_groupowner_backup_etc_passwd,  "/etc/passwd-",  "root")
DEF_FILE_GROUP(file_groupowner_backup_etc_group,   "/etc/group-",   "root")
DEF_FILE_GROUP(file_groupowner_backup_etc_shadow,  "/etc/shadow-",  "root")
DEF_FILE_GROUP(file_groupowner_backup_etc_gshadow, "/etc/gshadow-", "root")

/* Permissions: SCAP expects passwd/group at <= 0644; shadow/gshadow at <= 0640. */
DEF_FILE_MODE(file_permissions_etc_passwd,           "/etc/passwd",   0644)
DEF_FILE_MODE(file_permissions_etc_group,            "/etc/group",    0644)
DEF_FILE_MODE(file_permissions_etc_shadow,           "/etc/shadow",   0640)
DEF_FILE_MODE(file_permissions_etc_gshadow,          "/etc/gshadow",  0640)
DEF_FILE_MODE(file_permissions_backup_etc_passwd,    "/etc/passwd-",  0644)
DEF_FILE_MODE(file_permissions_backup_etc_group,     "/etc/group-",   0644)
DEF_FILE_MODE(file_permissions_backup_etc_shadow,    "/etc/shadow-",  0640)
DEF_FILE_MODE(file_permissions_backup_etc_gshadow,   "/etc/gshadow-", 0640)

/* Crontab and per-frequency cron directories: owner root, group root, mode <= 0700 */
DEF_FILE_OWNER(file_owner_crontab,         "/etc/crontab",        "root")
DEF_FILE_OWNER(file_owner_cron_d,          "/etc/cron.d",         "root")
DEF_FILE_OWNER(file_owner_cron_daily,      "/etc/cron.daily",     "root")
DEF_FILE_OWNER(file_owner_cron_hourly,     "/etc/cron.hourly",    "root")
DEF_FILE_OWNER(file_owner_cron_monthly,    "/etc/cron.monthly",   "root")
DEF_FILE_OWNER(file_owner_cron_weekly,     "/etc/cron.weekly",    "root")
DEF_FILE_GROUP(file_groupowner_crontab,       "/etc/crontab",      "root")
DEF_FILE_GROUP(file_groupowner_cron_d,        "/etc/cron.d",       "root")
DEF_FILE_GROUP(file_groupowner_cron_daily,    "/etc/cron.daily",   "root")
DEF_FILE_GROUP(file_groupowner_cron_hourly,   "/etc/cron.hourly",  "root")
DEF_FILE_GROUP(file_groupowner_cron_monthly,  "/etc/cron.monthly", "root")
DEF_FILE_GROUP(file_groupowner_cron_weekly,   "/etc/cron.weekly",  "root")
DEF_FILE_MODE(file_permissions_crontab,        "/etc/crontab",       0600)
DEF_FILE_MODE(file_permissions_cron_d,         "/etc/cron.d",        0700)
DEF_FILE_MODE(file_permissions_cron_daily,     "/etc/cron.daily",    0700)
DEF_FILE_MODE(file_permissions_cron_hourly,    "/etc/cron.hourly",   0700)
DEF_FILE_MODE(file_permissions_cron_monthly,   "/etc/cron.monthly",  0700)
DEF_FILE_MODE(file_permissions_cron_weekly,    "/etc/cron.weekly",   0700)

/* ---------- sysctl helpers ---------- */

static rule_result_t check_sysctl_equals(const char *key_slash, long expected) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/sys/%s", key_slash);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (errno == ENOENT) {
            return na_evidence("%s not present", path);
        }
        return check_error("unable to read sysctl");
    }
    long val = 0;
    int parsed = fscanf(fp, "%ld", &val);
    fclose(fp);
    if (parsed != 1) {
        return check_error("unable to parse sysctl value");
    }
    if (val == expected) {
        return pass_evidence("%s=%ld", key_slash, val);
    }
    return fail_evidence("%s=%ld (expected %ld)", key_slash, val, expected);
}

#define DEF_SYSCTL(name, key_slash, expected) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_sysctl_equals(key_slash, (long)(expected)); \
}

DEF_SYSCTL(sysctl_net_ipv6_conf_all_accept_ra,            "net/ipv6/conf/all/accept_ra",            0)
DEF_SYSCTL(sysctl_net_ipv6_conf_all_accept_redirects,     "net/ipv6/conf/all/accept_redirects",     0)
DEF_SYSCTL(sysctl_net_ipv6_conf_all_accept_source_route,  "net/ipv6/conf/all/accept_source_route",  0)
DEF_SYSCTL(sysctl_net_ipv6_conf_all_forwarding,           "net/ipv6/conf/all/forwarding",           0)
DEF_SYSCTL(sysctl_net_ipv6_conf_default_accept_ra,        "net/ipv6/conf/default/accept_ra",        0)
DEF_SYSCTL(sysctl_net_ipv6_conf_default_accept_redirects, "net/ipv6/conf/default/accept_redirects", 0)
DEF_SYSCTL(sysctl_net_ipv6_conf_default_accept_source_route,
           "net/ipv6/conf/default/accept_source_route", 0)
DEF_SYSCTL(sysctl_net_ipv4_conf_all_accept_redirects,     "net/ipv4/conf/all/accept_redirects",     0)
DEF_SYSCTL(sysctl_net_ipv4_conf_all_accept_source_route,  "net/ipv4/conf/all/accept_source_route",  0)
DEF_SYSCTL(sysctl_net_ipv4_conf_all_log_martians,         "net/ipv4/conf/all/log_martians",         1)
DEF_SYSCTL(sysctl_net_ipv4_conf_all_rp_filter,            "net/ipv4/conf/all/rp_filter",            1)
DEF_SYSCTL(sysctl_net_ipv4_conf_all_secure_redirects,     "net/ipv4/conf/all/secure_redirects",     0)
DEF_SYSCTL(sysctl_net_ipv4_conf_all_send_redirects,       "net/ipv4/conf/all/send_redirects",       0)
DEF_SYSCTL(sysctl_net_ipv4_conf_default_accept_redirects, "net/ipv4/conf/default/accept_redirects", 0)
DEF_SYSCTL(sysctl_net_ipv4_conf_default_accept_source_route,
           "net/ipv4/conf/default/accept_source_route", 0)
DEF_SYSCTL(sysctl_net_ipv4_conf_default_log_martians,     "net/ipv4/conf/default/log_martians",     1)
DEF_SYSCTL(sysctl_net_ipv4_conf_default_rp_filter,        "net/ipv4/conf/default/rp_filter",        1)
DEF_SYSCTL(sysctl_net_ipv4_conf_default_secure_redirects, "net/ipv4/conf/default/secure_redirects", 0)
DEF_SYSCTL(sysctl_net_ipv4_conf_default_send_redirects,   "net/ipv4/conf/default/send_redirects",   0)
DEF_SYSCTL(sysctl_net_ipv4_icmp_echo_ignore_broadcasts,   "net/ipv4/icmp_echo_ignore_broadcasts",   1)
DEF_SYSCTL(sysctl_net_ipv4_icmp_ignore_bogus_error_responses,
           "net/ipv4/icmp_ignore_bogus_error_responses", 1)
DEF_SYSCTL(sysctl_net_ipv4_tcp_syncookies,                "net/ipv4/tcp_syncookies",                1)
DEF_SYSCTL(sysctl_net_ipv4_ip_forward,                    "net/ipv4/ip_forward",                    0)
DEF_SYSCTL(sysctl_fs_suid_dumpable,                       "fs/suid_dumpable",                       0)
DEF_SYSCTL(sysctl_kernel_randomize_va_space,              "kernel/randomize_va_space",              2)

/* ---------- /proc/mounts helpers ---------- */

typedef struct {
    char *target;
    char *options;
} mount_entry_t;

static void free_mount_entries(mount_entry_t *entries, size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; ++i) {
        free(entries[i].target);
        free(entries[i].options);
    }
    free(entries);
}

static int load_mount_entries(mount_entry_t **out, size_t *out_count) {
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp) return -1;
    size_t cap = 64, count = 0;
    mount_entry_t *entries = calloc(cap, sizeof(mount_entry_t));
    if (!entries) { fclose(fp); return -1; }
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        char *saveptr = NULL;
        strtok_r(line, " \t\n", &saveptr);                  /* device */
        char *target  = strtok_r(NULL, " \t\n", &saveptr);
        strtok_r(NULL, " \t\n", &saveptr);                  /* fstype */
        char *options = strtok_r(NULL, " \t\n", &saveptr);
        if (!target || !options) continue;
        if (count == cap) {
            cap *= 2;
            mount_entry_t *tmp = realloc(entries, cap * sizeof(mount_entry_t));
            if (!tmp) { free_mount_entries(entries, count); fclose(fp); return -1; }
            entries = tmp;
        }
        entries[count].target  = strdup(target);
        entries[count].options = strdup(options);
        if (!entries[count].target || !entries[count].options) {
            free_mount_entries(entries, count + 1);
            fclose(fp);
            return -1;
        }
        count++;
    }
    fclose(fp);
    *out = entries;
    *out_count = count;
    return 0;
}

static bool mount_options_contain(const char *options, const char *token) {
    char *dup = strdup(options);
    if (!dup) return false;
    bool found = false;
    char *saveptr = NULL;
    for (char *t = strtok_r(dup, ",", &saveptr); t; t = strtok_r(NULL, ",", &saveptr)) {
        if (strcmp(t, token) == 0) { found = true; break; }
    }
    free(dup);
    return found;
}

static rule_result_t check_mount_option(const char *target, const char *option) {
    mount_entry_t *entries = NULL;
    size_t count = 0;
    if (load_mount_entries(&entries, &count) != 0) {
        return check_error("unable to read /proc/mounts");
    }
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(entries[i].target, target) == 0) {
            bool ok = mount_options_contain(entries[i].options, option);
            rule_result_t r = ok
                ? pass_evidence("%s mounted with %s", target, option)
                : fail_evidence("%s missing %s (options=%s)", target, option, entries[i].options);
            free_mount_entries(entries, count);
            return r;
        }
    }
    free_mount_entries(entries, count);
    return fail_evidence("%s is not a separate mount point", target);
}

#define DEF_MOUNT(name, target, option) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_mount_option(target, option); \
}

DEF_MOUNT(mount_option_dev_shm_nodev,       "/dev/shm",      "nodev")
DEF_MOUNT(mount_option_dev_shm_noexec,      "/dev/shm",      "noexec")
DEF_MOUNT(mount_option_dev_shm_nosuid,      "/dev/shm",      "nosuid")
DEF_MOUNT(mount_option_home_nodev,          "/home",         "nodev")
DEF_MOUNT(mount_option_home_nosuid,         "/home",         "nosuid")
DEF_MOUNT(mount_option_tmp_nodev,           "/tmp",          "nodev")
DEF_MOUNT(mount_option_tmp_noexec,          "/tmp",          "noexec")
DEF_MOUNT(mount_option_tmp_nosuid,          "/tmp",          "nosuid")
DEF_MOUNT(mount_option_var_nodev,           "/var",          "nodev")
DEF_MOUNT(mount_option_var_nosuid,          "/var",          "nosuid")
DEF_MOUNT(mount_option_var_log_nodev,       "/var/log",      "nodev")
DEF_MOUNT(mount_option_var_log_noexec,      "/var/log",      "noexec")
DEF_MOUNT(mount_option_var_log_nosuid,      "/var/log",      "nosuid")
DEF_MOUNT(mount_option_var_log_audit_nodev, "/var/log/audit","nodev")
DEF_MOUNT(mount_option_var_log_audit_noexec,"/var/log/audit","noexec")
DEF_MOUNT(mount_option_var_log_audit_nosuid,"/var/log/audit","nosuid")
DEF_MOUNT(mount_option_var_tmp_nodev,       "/var/tmp",      "nodev")
DEF_MOUNT(mount_option_var_tmp_noexec,      "/var/tmp",      "noexec")
DEF_MOUNT(mount_option_var_tmp_nosuid,      "/var/tmp",      "nosuid")

/* ---------- Account structural checks ---------- */

static rule_result_t check_accounts_no_uid_except_zero(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) return check_error("unable to open /etc/passwd");
    char line[4096];
    char offending[128] = "";
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *saveptr = NULL;
        char *user = strtok_r(line, ":", &saveptr);
        strtok_r(NULL, ":", &saveptr);              /* password */
        char *uid_str = strtok_r(NULL, ":", &saveptr);
        if (!user || !uid_str) continue;
        long uid_val = strtol(uid_str, NULL, 10);
        if (uid_val == 0 && strcmp(user, "root") != 0) {
            snprintf(offending, sizeof(offending), "%s", user);
            break;
        }
    }
    fclose(fp);
    if (offending[0]) {
        return fail_evidence("non-root account '%s' has UID 0", offending);
    }
    return pass_evidence("only root has UID 0");
}

static rule_result_t check_accounts_root_gid_zero(const rule_definition_t *rule) {
    (void)rule;
    struct passwd *pw = getpwnam("root");
    if (!pw) return check_error("root account not found");
    if (pw->pw_gid == 0) {
        return pass_evidence("root primary GID=0");
    }
    return fail_evidence("root primary GID=%u (expected 0)", (unsigned)pw->pw_gid);
}

static rule_result_t check_no_empty_passwords_etc_shadow(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/shadow", "r");
    if (!fp) {
        if (errno == EACCES) return check_error("/etc/shadow not readable (run as root)");
        return check_error("unable to open /etc/shadow");
    }
    char line[4096];
    char offending[128] = "";
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *saveptr = NULL;
        char *user = strtok_r(line, ":", &saveptr);
        char *pass = strtok_r(NULL, ":", &saveptr);
        if (!user || !pass) continue;
        if (pass[0] == '\0') {
            snprintf(offending, sizeof(offending), "%s", user);
            break;
        }
    }
    fclose(fp);
    if (offending[0]) {
        return fail_evidence("account '%s' has empty password", offending);
    }
    return pass_evidence("no accounts with empty password");
}

static rule_result_t check_gid_passwd_group_same(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) return check_error("unable to open /etc/passwd");
    char line[4096];
    char offending[256] = "";
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *saveptr = NULL;
        char *user = strtok_r(line, ":", &saveptr);
        strtok_r(NULL, ":", &saveptr);              /* password */
        strtok_r(NULL, ":", &saveptr);              /* uid */
        char *gid_str = strtok_r(NULL, ":", &saveptr);
        if (!user || !gid_str) continue;
        long gid_val = strtol(gid_str, NULL, 10);
        if (gid_val < 0) continue;
        if (getgrgid((gid_t)gid_val) == NULL) {
            snprintf(offending, sizeof(offending), "%s GID=%ld", user, gid_val);
            break;
        }
    }
    fclose(fp);
    if (offending[0]) {
        return fail_evidence("undefined group: %s", offending);
    }
    return pass_evidence("all passwd GIDs defined in /etc/group");
}

static bool shell_is_nologin(const char *shell) {
    if (!shell || !*shell) return true;       /* empty shell counts as nologin */
    return strstr(shell, "nologin") != NULL
        || strstr(shell, "/false") != NULL
        || strcmp(shell, "/sbin/nologin") == 0
        || strcmp(shell, "/usr/sbin/nologin") == 0
        || strcmp(shell, "/bin/false") == 0
        || strcmp(shell, "/usr/bin/false") == 0;
}

static rule_result_t check_no_shelllogin_for_systemaccounts(const rule_definition_t *rule) {
    (void)rule;
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) return check_error("unable to open /etc/passwd");
    char line[4096];
    char offending[128] = "";
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *saveptr = NULL;
        char *user = strtok_r(line, ":", &saveptr);
        strtok_r(NULL, ":", &saveptr);              /* password */
        char *uid_str = strtok_r(NULL, ":", &saveptr);
        strtok_r(NULL, ":", &saveptr);              /* gid */
        strtok_r(NULL, ":", &saveptr);              /* gecos */
        strtok_r(NULL, ":", &saveptr);              /* home */
        char *shell = strtok_r(NULL, ":", &saveptr);
        if (!user || !uid_str) continue;
        if (strcmp(user, "root") == 0) continue;
        if (strcmp(user, "sync") == 0 || strcmp(user, "shutdown") == 0 || strcmp(user, "halt") == 0) {
            continue;                               /* canonical exempt accounts */
        }
        long uid_val = strtol(uid_str, NULL, 10);
        if (uid_val == 0 || uid_val >= 1000) continue;
        if (!shell_is_nologin(shell)) {
            snprintf(offending, sizeof(offending), "%s (uid=%ld, shell=%s)",
                     user, uid_val, shell ? shell : "");
            break;
        }
    }
    fclose(fp);
    if (offending[0]) {
        return fail_evidence("system account has login shell: %s", offending);
    }
    return pass_evidence("no system accounts run a login shell");
}

/* ---------- /etc/login.defs numeric reader ---------- */

static int read_login_defs_long(const char *key, long *out) {
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines("/etc/login.defs", &lines, &count) != 0) return -1;
    bool found = false;
    long value = 0;
    size_t klen = strlen(key);
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (strncasecmp(p, key, klen) == 0
            && (p[klen] == ' ' || p[klen] == '\t')) {
            char *val = p + klen;
            while (*val && isspace((unsigned char)*val)) val++;
            char *endp = NULL;
            errno = 0;
            long parsed = strtol(val, &endp, 0);   /* base 0: accepts octal "027" */
            if (endp != val && errno == 0) {
                value = parsed;
                found = true;
                break;                              /* first matching wins */
            }
        }
    }
    free_lines(lines, count);
    if (!found) return -1;
    *out = value;
    return 0;
}

static rule_result_t check_accounts_maximum_age_login_defs(const rule_definition_t *rule) {
    (void)rule;
    long v;
    if (read_login_defs_long("PASS_MAX_DAYS", &v) != 0) {
        return check_error("PASS_MAX_DAYS not set in /etc/login.defs");
    }
    if (v > 0 && v <= 365) return pass_evidence("PASS_MAX_DAYS=%ld", v);
    return fail_evidence("PASS_MAX_DAYS=%ld (expected 1-365)", v);
}

static rule_result_t check_accounts_minimum_age_login_defs(const rule_definition_t *rule) {
    (void)rule;
    long v;
    if (read_login_defs_long("PASS_MIN_DAYS", &v) != 0) {
        return check_error("PASS_MIN_DAYS not set in /etc/login.defs");
    }
    if (v >= 1) return pass_evidence("PASS_MIN_DAYS=%ld", v);
    return fail_evidence("PASS_MIN_DAYS=%ld (expected >=1)", v);
}

static rule_result_t check_accounts_password_warn_age_login_defs(const rule_definition_t *rule) {
    (void)rule;
    long v;
    if (read_login_defs_long("PASS_WARN_AGE", &v) != 0) {
        return check_error("PASS_WARN_AGE not set in /etc/login.defs");
    }
    if (v >= 7) return pass_evidence("PASS_WARN_AGE=%ld", v);
    return fail_evidence("PASS_WARN_AGE=%ld (expected >=7)", v);
}

static rule_result_t check_accounts_umask_etc_login_defs(const rule_definition_t *rule) {
    (void)rule;
    long v;
    if (read_login_defs_long("UMASK", &v) != 0) {
        return check_error("UMASK not set in /etc/login.defs");
    }
    /* Accept 027 (octal) or 077 — anything <= 027 group/other strictness. */
    if (v == 027 || v == 077) return pass_evidence("UMASK=%03lo", v);
    return fail_evidence("UMASK=%03lo (expected 027 or 077)", v);
}

/* ---------- umask in shell rc files ---------- */

static rule_result_t check_umask_in_shell_file(const char *path) {
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(path, &lines, &count) != 0) {
        return na_evidence("%s does not exist", path);
    }
    long strictest = -1;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (strncmp(p, "umask", 5) != 0 || !(p[5] == ' ' || p[5] == '\t')) continue;
        char *val = p + 5;
        while (*val && isspace((unsigned char)*val)) val++;
        char *endp = NULL;
        errno = 0;
        long parsed = strtol(val, &endp, 8);        /* umask is octal */
        if (endp != val && errno == 0) {
            if (strictest < 0 || parsed > strictest) strictest = parsed;
        }
    }
    free_lines(lines, count);
    if (strictest < 0) {
        return fail_evidence("no umask directive found in %s", path);
    }
    if (strictest == 027 || strictest == 077) {
        return pass_evidence("%s umask=%03lo", path, strictest);
    }
    return fail_evidence("%s umask=%03lo (expected 027 or 077)", path, strictest);
}

static rule_result_t check_accounts_umask_etc_bashrc(const rule_definition_t *rule) {
    (void)rule;
    return check_umask_in_shell_file("/etc/bash.bashrc");
}

static rule_result_t check_accounts_umask_etc_profile(const rule_definition_t *rule) {
    (void)rule;
    return check_umask_in_shell_file("/etc/profile");
}

/* ---------- TMOUT in /etc/profile or /etc/profile.d ---------- */

static rule_result_t check_accounts_tmout(const rule_definition_t *rule) {
    (void)rule;
    const char *paths[] = { "/etc/profile", "/etc/bash.bashrc", NULL };
    long tmout = -1;
    char source[128] = "";
    for (size_t i = 0; paths[i]; ++i) {
        char **lines = NULL;
        size_t count = 0;
        if (load_file_lines(paths[i], &lines, &count) != 0) continue;
        for (size_t j = 0; j < count; ++j) {
            const char *needle = strstr(lines[j], "TMOUT");
            if (!needle) continue;
            const char *eq = strchr(needle, '=');
            if (!eq) continue;
            const char *val = eq + 1;
            while (*val && isspace((unsigned char)*val)) val++;
            char *endp = NULL;
            errno = 0;
            long parsed = strtol(val, &endp, 10);
            if (endp != val && errno == 0 && parsed > 0) {
                tmout = parsed;
                snprintf(source, sizeof(source), "%s", paths[i]);
                break;
            }
        }
        free_lines(lines, count);
        if (tmout > 0) break;
    }
    if (tmout > 0 && tmout <= 900) {
        return pass_evidence("TMOUT=%ld in %s", tmout, source);
    }
    if (tmout > 900) {
        return fail_evidence("TMOUT=%ld in %s (expected 1-900)", tmout, source);
    }
    return fail_evidence("TMOUT not set in /etc/profile or /etc/bash.bashrc");
}

/* ---------- Per-user home directory and dotfile rules ---------- */

static bool user_is_interactive(const struct passwd *pw) {
    if (!pw) return false;
    if (pw->pw_uid < 1000) return false;
    if (pw->pw_uid == 65534) return false;          /* nobody */
    if (!pw->pw_shell || !*pw->pw_shell) return false;
    return !shell_is_nologin(pw->pw_shell);
}

typedef rule_result_t (*per_user_check_fn)(const struct passwd *pw);

static rule_result_t for_each_interactive_user(per_user_check_fn fn) {
    setpwent();
    struct passwd *pw;
    bool any = false;
    while ((pw = getpwent()) != NULL) {
        if (!user_is_interactive(pw)) continue;
        any = true;
        rule_result_t r = fn(pw);
        if (r.status == RULE_STATUS_FAIL || r.status == RULE_STATUS_ERROR) {
            endpwent();
            return r;
        }
    }
    endpwent();
    if (!any) {
        return na_evidence("no interactive users found");
    }
    return pass_evidence("all interactive users compliant");
}

static rule_result_t per_user_no_dotfile(const struct passwd *pw, const char *dotfile) {
    if (!pw->pw_dir || !*pw->pw_dir) {
        return pass_evidence("%s has no home directory set", pw->pw_name);
    }
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", pw->pw_dir, dotfile);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return check_error("home path too long");
    }
    struct stat st;
    if (lstat(path, &st) == 0) {
        return fail_evidence("%s exists for user %s", path, pw->pw_name);
    }
    return pass_evidence("%s absent", path);
}

static rule_result_t per_user_no_forward(const struct passwd *pw) {
    return per_user_no_dotfile(pw, ".forward");
}

static rule_result_t per_user_no_netrc(const struct passwd *pw) {
    return per_user_no_dotfile(pw, ".netrc");
}

static rule_result_t per_user_home_exists(const struct passwd *pw) {
    if (!pw->pw_dir || !*pw->pw_dir) {
        return fail_evidence("%s has no home directory set", pw->pw_name);
    }
    struct stat st;
    if (stat(pw->pw_dir, &st) != 0) {
        return fail_evidence("%s missing home directory %s", pw->pw_name, pw->pw_dir);
    }
    if (!S_ISDIR(st.st_mode)) {
        return fail_evidence("%s home %s is not a directory", pw->pw_name, pw->pw_dir);
    }
    return pass_evidence("%s home %s exists", pw->pw_name, pw->pw_dir);
}

static rule_result_t per_user_home_owner(const struct passwd *pw) {
    if (!pw->pw_dir || !*pw->pw_dir) return pass_evidence("%s no home set", pw->pw_name);
    struct stat st;
    if (stat(pw->pw_dir, &st) != 0) return pass_evidence("%s home missing", pw->pw_name);
    if (st.st_uid != pw->pw_uid) {
        return fail_evidence("%s home %s owned by uid=%u (expected %u)",
                             pw->pw_name, pw->pw_dir, (unsigned)st.st_uid, (unsigned)pw->pw_uid);
    }
    return pass_evidence("%s home owner OK", pw->pw_name);
}

static rule_result_t per_user_home_group(const struct passwd *pw) {
    if (!pw->pw_dir || !*pw->pw_dir) return pass_evidence("%s no home set", pw->pw_name);
    struct stat st;
    if (stat(pw->pw_dir, &st) != 0) return pass_evidence("%s home missing", pw->pw_name);
    if (st.st_gid != pw->pw_gid) {
        return fail_evidence("%s home %s group=%u (expected primary %u)",
                             pw->pw_name, pw->pw_dir, (unsigned)st.st_gid, (unsigned)pw->pw_gid);
    }
    return pass_evidence("%s home group OK", pw->pw_name);
}

static rule_result_t per_user_home_mode(const struct passwd *pw) {
    if (!pw->pw_dir || !*pw->pw_dir) return pass_evidence("%s no home set", pw->pw_name);
    struct stat st;
    if (stat(pw->pw_dir, &st) != 0) return pass_evidence("%s home missing", pw->pw_name);
    mode_t actual = st.st_mode & 07777;
    if ((actual & ~(mode_t)0750) != 0) {
        return fail_evidence("%s home %s mode=%04o (expected <= 0750)",
                             pw->pw_name, pw->pw_dir, actual);
    }
    return pass_evidence("%s home mode=%04o", pw->pw_name, actual);
}

static rule_result_t per_user_dotfile_owner(const struct passwd *pw) {
    if (!pw->pw_dir || !*pw->pw_dir) return pass_evidence("%s no home", pw->pw_name);
    char pattern[PATH_MAX];
    int n = snprintf(pattern, sizeof(pattern), "%s", pw->pw_dir);
    if (n < 0 || (size_t)n >= sizeof(pattern)) return check_error("home path too long");
    /* Inspect a fixed list of common init dotfiles rather than scanning the directory. */
    const char *dotfiles[] = {
        ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".cshrc",
        ".tcshrc", ".login", ".kshrc", NULL
    };
    for (size_t i = 0; dotfiles[i]; ++i) {
        char path[PATH_MAX];
        int m = snprintf(path, sizeof(path), "%s/%s", pw->pw_dir, dotfiles[i]);
        if (m < 0 || (size_t)m >= sizeof(path)) continue;
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (st.st_uid != pw->pw_uid) {
            return fail_evidence("%s owned by uid=%u (expected %u)",
                                 path, (unsigned)st.st_uid, (unsigned)pw->pw_uid);
        }
    }
    return pass_evidence("%s init dotfiles owned by user", pw->pw_name);
}

static rule_result_t per_user_dotfile_group(const struct passwd *pw) {
    if (!pw->pw_dir || !*pw->pw_dir) return pass_evidence("%s no home", pw->pw_name);
    const char *dotfiles[] = {
        ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".cshrc",
        ".tcshrc", ".login", ".kshrc", NULL
    };
    for (size_t i = 0; dotfiles[i]; ++i) {
        char path[PATH_MAX];
        int m = snprintf(path, sizeof(path), "%s/%s", pw->pw_dir, dotfiles[i]);
        if (m < 0 || (size_t)m >= sizeof(path)) continue;
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (st.st_gid != pw->pw_gid) {
            return fail_evidence("%s group=%u (expected primary %u)",
                                 path, (unsigned)st.st_gid, (unsigned)pw->pw_gid);
        }
    }
    return pass_evidence("%s init dotfiles group-owned by primary group", pw->pw_name);
}

static rule_result_t check_no_forward_files(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_user(per_user_no_forward);
}

static rule_result_t check_no_netrc_files(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_user(per_user_no_netrc);
}

static rule_result_t check_accounts_user_interactive_home_directory_exists(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_user(per_user_home_exists);
}

static rule_result_t check_file_ownership_home_directories(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_user(per_user_home_owner);
}

static rule_result_t check_file_groupownership_home_directories(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_user(per_user_home_group);
}

static rule_result_t check_file_permissions_home_directories(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_user(per_user_home_mode);
}

static rule_result_t check_accounts_user_dot_user_ownership(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_user(per_user_dotfile_owner);
}

static rule_result_t check_accounts_user_dot_group_ownership(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_user(per_user_dotfile_group);
}

/* ---------- Kernel module disabled ---------- */

static bool modprobe_disables_module(const char *dir, const char *module) {
    DIR *d = opendir(dir);
    if (!d) return false;
    bool disabled = false;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        bool is_conf = nlen > 5 && strcmp(name + nlen - 5, ".conf") == 0;
        if (!is_conf) continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        char **lines = NULL;
        size_t count = 0;
        if (load_file_lines(path, &lines, &count) != 0) continue;
        for (size_t i = 0; i < count && !disabled; ++i) {
            char *p = lines[i];
            while (isspace((unsigned char)*p)) p++;
            if (*p == '#' || *p == '\0') continue;
            /* blacklist <module> */
            if (strncmp(p, "blacklist", 9) == 0 && isspace((unsigned char)p[9])) {
                char *m = p + 9;
                while (isspace((unsigned char)*m)) m++;
                if (strcmp(m, module) == 0) { disabled = true; break; }
            }
            /* install <module> /bin/true|false  (or /sbin/...) */
            if (strncmp(p, "install", 7) == 0 && isspace((unsigned char)p[7])) {
                char *m = p + 7;
                while (isspace((unsigned char)*m)) m++;
                size_t mlen = strlen(module);
                if (strncmp(m, module, mlen) == 0 && isspace((unsigned char)m[mlen])) {
                    char *cmd = m + mlen;
                    while (isspace((unsigned char)*cmd)) cmd++;
                    if (strstr(cmd, "/true") || strstr(cmd, "/false")) {
                        disabled = true;
                        break;
                    }
                }
            }
        }
        free_lines(lines, count);
        if (disabled) break;
    }
    closedir(d);
    return disabled;
}

static bool module_currently_loaded(const char *module) {
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) return false;
    char line[1024];
    bool loaded = false;
    size_t mlen = strlen(module);
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, module, mlen) == 0 && line[mlen] == ' ') {
            loaded = true;
            break;
        }
    }
    fclose(fp);
    return loaded;
}

static rule_result_t check_kernel_module_disabled(const char *module) {
    if (module_currently_loaded(module)) {
        return fail_evidence("module %s currently loaded", module);
    }
    bool disabled = modprobe_disables_module("/etc/modprobe.d", module)
                 || modprobe_disables_module("/lib/modprobe.d", module)
                 || modprobe_disables_module("/run/modprobe.d", module)
                 || modprobe_disables_module("/usr/lib/modprobe.d", module);
    if (disabled) {
        return pass_evidence("module %s blacklisted or install-disabled", module);
    }
    return fail_evidence("module %s not blacklisted in any modprobe.d", module);
}

static rule_result_t check_kernel_module_cramfs_disabled(const rule_definition_t *rule) {
    (void)rule; return check_kernel_module_disabled("cramfs");
}

static rule_result_t check_kernel_module_usb_storage_disabled(const rule_definition_t *rule) {
    (void)rule; return check_kernel_module_disabled("usb-storage");
}

/* ---------- systemctl-driven service state ---------- */

/* Restrict unit names to a conservative character set to keep the popen command safe. */
static bool unit_name_is_safe(const char *unit) {
    if (!unit || !*unit) return false;
    for (const char *p = unit; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (!isalnum(c) && c != '.' && c != '_' && c != '-' && c != '@' && c != ':') {
            return false;
        }
    }
    return true;
}

static int systemctl_query(const char *verb, const char *unit, char *out, size_t out_size) {
    static const char *candidates[] = { "/usr/bin/systemctl", "/bin/systemctl", NULL };
    const char *bin = NULL;
    for (size_t i = 0; candidates[i]; ++i) {
        if (access(candidates[i], X_OK) == 0) { bin = candidates[i]; break; }
    }
    if (!bin) return -1;
    if (!unit_name_is_safe(unit)) return -1;

    char cmd[512];
    int n = snprintf(cmd, sizeof(cmd), "%s %s %s 2>/dev/null", bin, verb, unit);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return -1;

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    out[0] = '\0';
    if (fgets(out, out_size, fp)) {
        char *nl = strchr(out, '\n');
        if (nl) *nl = '\0';
    }
    pclose(fp);
    return 0;
}

static rule_result_t check_service_enabled(const char *unit) {
    char out[64];
    if (systemctl_query("is-enabled", unit, out, sizeof(out)) != 0) {
        return check_error("systemctl not available");
    }
    if (out[0] == '\0') {
        return fail_evidence("%s: no unit file found", unit);
    }
    if (strcmp(out, "enabled") == 0 || strcmp(out, "enabled-runtime") == 0
        || strcmp(out, "static") == 0 || strcmp(out, "alias") == 0
        || strcmp(out, "indirect") == 0) {
        return pass_evidence("%s is-enabled=%s", unit, out);
    }
    return fail_evidence("%s is-enabled=%s", unit, out);
}

static rule_result_t check_service_disabled(const char *unit) {
    char out[64];
    if (systemctl_query("is-enabled", unit, out, sizeof(out)) != 0) {
        return check_error("systemctl not available");
    }
    if (out[0] == '\0' || strcmp(out, "not-found") == 0) {
        return pass_evidence("%s: unit not present", unit);
    }
    if (strcmp(out, "disabled") == 0 || strcmp(out, "masked") == 0
        || strcmp(out, "masked-runtime") == 0) {
        return pass_evidence("%s is-enabled=%s", unit, out);
    }
    return fail_evidence("%s is-enabled=%s (expected disabled/masked)", unit, out);
}

#define DEF_SERVICE_ENABLED(name, unit) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_service_enabled(unit); \
}

#define DEF_SERVICE_DISABLED(name, unit) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_service_disabled(unit); \
}

DEF_SERVICE_ENABLED(service_cron_enabled,                 "cron.service")
DEF_SERVICE_ENABLED(service_rsyslog_enabled,              "rsyslog.service")
DEF_SERVICE_ENABLED(service_systemd_journald_enabled,     "systemd-journald.service")
DEF_SERVICE_ENABLED(service_nftables_enabled,             "nftables.service")
DEF_SERVICE_ENABLED(service_ufw_enabled,                  "ufw.service")
DEF_SERVICE_DISABLED(service_autofs_disabled,             "autofs.service")
DEF_SERVICE_DISABLED(service_apport_disabled,             "apport.service")
DEF_SERVICE_DISABLED(service_avahi_daemon_disabled,       "avahi-daemon.service")
DEF_SERVICE_DISABLED(socket_systemd_journal_remote_disabled, "systemd-journal-remote.socket")

/* ---------- dpkg-query driven package state ---------- */

static bool package_name_is_safe(const char *pkg) {
    if (!pkg || !*pkg) return false;
    for (const char *p = pkg; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        /* Debian policy allows lowercase letters, digits, +, -, . in package names. */
        if (!(islower(c) || isdigit(c)) && c != '+' && c != '-' && c != '.') {
            return false;
        }
    }
    return true;
}

static int dpkg_is_installed(const char *pkg, bool *installed_out) {
    static const char *candidates[] = { "/usr/bin/dpkg-query", "/bin/dpkg-query", NULL };
    const char *bin = NULL;
    for (size_t i = 0; candidates[i]; ++i) {
        if (access(candidates[i], X_OK) == 0) { bin = candidates[i]; break; }
    }
    if (!bin) return -1;
    if (!package_name_is_safe(pkg)) return -1;

    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s -W -f='${Status}\\n' %s 2>/dev/null", bin, pkg);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return -1;

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    char status[128] = "";
    if (fgets(status, sizeof(status), fp) == NULL) {
        status[0] = '\0';
    }
    pclose(fp);
    *installed_out = (strstr(status, "install ok installed") != NULL);
    return 0;
}

static rule_result_t check_package_installed(const char *pkg) {
    bool installed = false;
    if (dpkg_is_installed(pkg, &installed) != 0) {
        return check_error("dpkg-query not available");
    }
    return installed
        ? pass_evidence("%s installed", pkg)
        : fail_evidence("%s not installed", pkg);
}

static rule_result_t check_package_removed(const char *pkg) {
    bool installed = false;
    if (dpkg_is_installed(pkg, &installed) != 0) {
        return check_error("dpkg-query not available");
    }
    return installed
        ? fail_evidence("%s installed (expected removed)", pkg)
        : pass_evidence("%s not installed", pkg);
}

#define DEF_PACKAGE_INSTALLED(name, pkg) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_package_installed(pkg); \
}

#define DEF_PACKAGE_REMOVED(name, pkg) \
static rule_result_t check_##name(const rule_definition_t *rule) { \
    (void)rule; return check_package_removed(pkg); \
}

DEF_PACKAGE_INSTALLED(package_apparmor_installed,                "apparmor")
DEF_PACKAGE_INSTALLED(package_rsyslog_installed,                 "rsyslog")
DEF_PACKAGE_INSTALLED(package_systemd_journal_remote_installed,  "systemd-journal-remote")
DEF_PACKAGE_INSTALLED(package_iptables_installed,                "iptables")
DEF_PACKAGE_INSTALLED(package_nftables_installed,                "nftables")
DEF_PACKAGE_REMOVED(package_iptables_persistent_removed,         "iptables-persistent")
DEF_PACKAGE_REMOVED(package_ufw_removed,                         "ufw")
DEF_PACKAGE_REMOVED(package_avahi_removed,                       "avahi-daemon")

/* ---------- Directory-walking helpers ---------- */

typedef enum {
    DIRWALK_OWNER,
    DIRWALK_GROUP,
    DIRWALK_MODE,
} dirwalk_kind_t;

static rule_result_t walk_dir_files(const char *dir, dirwalk_kind_t kind,
                                    const char *expected_str, mode_t expected_mode) {
    DIR *d = opendir(dir);
    if (!d) {
        if (errno == ENOENT) return na_evidence("%s does not exist", dir);
        return check_error("unable to opendir");
    }
    struct dirent *ent;
    rule_result_t result = pass_evidence("all files in %s compliant", dir);
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        if (kind == DIRWALK_OWNER) {
            struct passwd *pw = getpwuid(st.st_uid);
            if (!pw || strcmp(pw->pw_name, expected_str) != 0) {
                result = fail_evidence("%s owner=%s (expected %s)", path,
                                       pw ? pw->pw_name : "?", expected_str);
                break;
            }
        } else if (kind == DIRWALK_GROUP) {
            struct group *gr = getgrgid(st.st_gid);
            if (!gr || strcmp(gr->gr_name, expected_str) != 0) {
                result = fail_evidence("%s group=%s (expected %s)", path,
                                       gr ? gr->gr_name : "?", expected_str);
                break;
            }
        } else if (kind == DIRWALK_MODE) {
            mode_t actual = st.st_mode & 07777;
            if ((actual & ~expected_mode) != 0) {
                result = fail_evidence("%s mode=%04o (expected <= %04o)",
                                       path, actual, expected_mode);
                break;
            }
        }
    }
    closedir(d);
    return result;
}

/* ---------- Audit subsystem files / binaries ---------- */

DEF_FILE_MODE(file_permissions_etc_audit_auditd_conf, "/etc/audit/auditd.conf", 0640)

static rule_result_t check_file_permissions_etc_audit_rulesd(const rule_definition_t *rule) {
    (void)rule;
    return walk_dir_files("/etc/audit/rules.d", DIRWALK_MODE, NULL, 0640);
}

static rule_result_t check_file_ownership_audit_configuration(const rule_definition_t *rule) {
    (void)rule;
    rule_result_t r = check_file_owner_named("/etc/audit/auditd.conf", "root");
    if (r.status != RULE_STATUS_PASS) return r;
    return walk_dir_files("/etc/audit/rules.d", DIRWALK_OWNER, "root", 0);
}

static rule_result_t check_file_groupownership_audit_configuration(const rule_definition_t *rule) {
    (void)rule;
    rule_result_t r = check_file_group_named("/etc/audit/auditd.conf", "root");
    if (r.status != RULE_STATUS_PASS) return r;
    return walk_dir_files("/etc/audit/rules.d", DIRWALK_GROUP, "root", 0);
}

/* /var/log/audit log files */
DEF_FILE_MODE(directory_permissions_var_log_audit_dir, "/var/log/audit", 0750)
static rule_result_t check_file_ownership_var_log_audit_stig(const rule_definition_t *rule) {
    (void)rule; return walk_dir_files("/var/log/audit", DIRWALK_OWNER, "root", 0);
}
static rule_result_t check_file_group_ownership_var_log_audit(const rule_definition_t *rule) {
    (void)rule; return walk_dir_files("/var/log/audit", DIRWALK_GROUP, "root", 0);
}
static rule_result_t check_file_permissions_var_log_audit(const rule_definition_t *rule) {
    (void)rule; return walk_dir_files("/var/log/audit", DIRWALK_MODE, NULL, 0640);
}

/* Audit binaries: auditctl, auditd, aureport, ausearch, autrace, augenrules */
static const char *AUDIT_BINARIES[] = {
    "/sbin/auditctl", "/usr/sbin/auditctl",
    "/sbin/auditd", "/usr/sbin/auditd",
    "/sbin/aureport", "/usr/sbin/aureport",
    "/sbin/ausearch", "/usr/sbin/ausearch",
    "/sbin/autrace", "/usr/sbin/autrace",
    "/sbin/augenrules", "/usr/sbin/augenrules",
    NULL,
};

static rule_result_t check_audit_binaries_attr(dirwalk_kind_t kind, const char *expected, mode_t mode_max) {
    bool any_seen = false;
    for (size_t i = 0; AUDIT_BINARIES[i]; ++i) {
        struct stat st;
        if (stat(AUDIT_BINARIES[i], &st) != 0) continue;
        any_seen = true;
        if (kind == DIRWALK_OWNER) {
            struct passwd *pw = getpwuid(st.st_uid);
            if (!pw || strcmp(pw->pw_name, expected) != 0) {
                return fail_evidence("%s owner=%s (expected %s)",
                                     AUDIT_BINARIES[i], pw ? pw->pw_name : "?", expected);
            }
        } else if (kind == DIRWALK_GROUP) {
            struct group *gr = getgrgid(st.st_gid);
            if (!gr || strcmp(gr->gr_name, expected) != 0) {
                return fail_evidence("%s group=%s (expected %s)",
                                     AUDIT_BINARIES[i], gr ? gr->gr_name : "?", expected);
            }
        } else if (kind == DIRWALK_MODE) {
            mode_t actual = st.st_mode & 07777;
            if ((actual & ~mode_max) != 0) {
                return fail_evidence("%s mode=%04o (expected <= %04o)",
                                     AUDIT_BINARIES[i], actual, mode_max);
            }
        }
    }
    if (!any_seen) return na_evidence("audit binaries not installed");
    return pass_evidence("all installed audit binaries compliant");
}

static rule_result_t check_file_ownership_audit_binaries(const rule_definition_t *rule) {
    (void)rule; return check_audit_binaries_attr(DIRWALK_OWNER, "root", 0);
}
static rule_result_t check_file_groupownership_audit_binaries(const rule_definition_t *rule) {
    (void)rule; return check_audit_binaries_attr(DIRWALK_GROUP, "root", 0);
}
static rule_result_t check_file_permissions_audit_binaries(const rule_definition_t *rule) {
    (void)rule; return check_audit_binaries_attr(DIRWALK_MODE, NULL, 0755);
}

/* ---------- GRUB config ownership / perms ---------- */

static rule_result_t check_file_owner_grub2_cfg(const rule_definition_t *rule) {
    (void)rule;
    const char *paths[] = { "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/efi/EFI/debian/grub.cfg", NULL };
    for (size_t i = 0; paths[i]; ++i) {
        struct stat st;
        if (stat(paths[i], &st) == 0) {
            return check_file_owner_named(paths[i], "root");
        }
    }
    return na_evidence("grub.cfg not found in known locations");
}

static rule_result_t check_file_permissions_grub2_cfg(const rule_definition_t *rule) {
    (void)rule;
    const char *paths[] = { "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/efi/EFI/debian/grub.cfg", NULL };
    for (size_t i = 0; paths[i]; ++i) {
        struct stat st;
        if (stat(paths[i], &st) == 0) {
            return check_file_mode_max(paths[i], 0700);
        }
    }
    return na_evidence("grub.cfg not found in known locations");
}

/* ---------- journald.conf simple key/value ---------- */

static int read_keyvalue_from_file(const char *path, const char *key, char *out, size_t out_size) {
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(path, &lines, &count) != 0) return -1;
    bool found = false;
    size_t klen = strlen(key);
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            char *val = p + klen + 1;
            while (*val && isspace((unsigned char)*val)) val++;
            snprintf(out, out_size, "%s", val);
            char *end = out + strlen(out);
            while (end > out && isspace((unsigned char)end[-1])) end--;
            *end = '\0';
            found = true;
            break;
        }
    }
    free_lines(lines, count);
    return found ? 0 : -1;
}

static rule_result_t check_journald_compress(const rule_definition_t *rule) {
    (void)rule;
    char val[64];
    if (read_keyvalue_from_file("/etc/systemd/journald.conf", "Compress", val, sizeof(val)) != 0) {
        return fail_evidence("Compress= not set in /etc/systemd/journald.conf");
    }
    if (strcasecmp(val, "yes") == 0 || strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0) {
        return pass_evidence("Compress=%s", val);
    }
    return fail_evidence("Compress=%s (expected yes)", val);
}

static rule_result_t check_journald_storage(const rule_definition_t *rule) {
    (void)rule;
    char val[64];
    if (read_keyvalue_from_file("/etc/systemd/journald.conf", "Storage", val, sizeof(val)) != 0) {
        return fail_evidence("Storage= not set in /etc/systemd/journald.conf");
    }
    if (strcmp(val, "persistent") == 0) {
        return pass_evidence("Storage=%s", val);
    }
    return fail_evidence("Storage=%s (expected persistent)", val);
}

/* ---------- rsyslog FileCreateMode ---------- */

static int rsyslog_filecreatemode_in_file(const char *path, long *out) {
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(path, &lines, &count) != 0) return -1;
    bool found = false;
    long strictest = -1;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (strncmp(p, "$FileCreateMode", 15) != 0) continue;
        if (!isspace((unsigned char)p[15])) continue;
        char *val = p + 15;
        while (isspace((unsigned char)*val)) val++;
        char *endp = NULL;
        errno = 0;
        long parsed = strtol(val, &endp, 8);
        if (endp != val && errno == 0) {
            if (!found || parsed > strictest) strictest = parsed;
            found = true;
        }
    }
    free_lines(lines, count);
    if (!found) return -1;
    *out = strictest;
    return 0;
}

static rule_result_t check_rsyslog_filecreatemode(const rule_definition_t *rule) {
    (void)rule;
    long mode = -1;
    long candidate = -1;
    if (rsyslog_filecreatemode_in_file("/etc/rsyslog.conf", &candidate) == 0) {
        mode = candidate;
    }
    DIR *d = opendir("/etc/rsyslog.d");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            size_t nlen = strlen(ent->d_name);
            if (nlen <= 5 || strcmp(ent->d_name + nlen - 5, ".conf") != 0) continue;
            char path[PATH_MAX];
            int n = snprintf(path, sizeof(path), "/etc/rsyslog.d/%s", ent->d_name);
            if (n < 0 || (size_t)n >= sizeof(path)) continue;
            if (rsyslog_filecreatemode_in_file(path, &candidate) == 0) {
                if (mode < 0 || candidate > mode) mode = candidate;
            }
        }
        closedir(d);
    }
    if (mode < 0) {
        return fail_evidence("$FileCreateMode not set in rsyslog config");
    }
    if ((mode & ~(long)0640) == 0) {
        return pass_evidence("$FileCreateMode=%04lo", mode);
    }
    return fail_evidence("$FileCreateMode=%04lo (expected <= 0640)", mode);
}

/* ---------- limits.conf core dumps ---------- */

static bool limits_file_disables_coredumps(const char *path) {
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(path, &lines, &count) != 0) return false;
    bool ok = false;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        /* Match: "* hard core 0" (whitespace-separated) */
        char *saveptr = NULL;
        char *dup = strdup(p);
        if (!dup) continue;
        char *domain = strtok_r(dup, " \t", &saveptr);
        char *type   = strtok_r(NULL, " \t", &saveptr);
        char *item   = strtok_r(NULL, " \t", &saveptr);
        char *value  = strtok_r(NULL, " \t", &saveptr);
        if (domain && type && item && value
            && strcmp(domain, "*") == 0
            && strcmp(type, "hard") == 0
            && strcmp(item, "core") == 0
            && strcmp(value, "0") == 0) {
            ok = true;
        }
        free(dup);
        if (ok) break;
    }
    free_lines(lines, count);
    return ok;
}

static rule_result_t check_disable_users_coredumps(const rule_definition_t *rule) {
    (void)rule;
    if (limits_file_disables_coredumps("/etc/security/limits.conf")) {
        return pass_evidence("'* hard core 0' set in /etc/security/limits.conf");
    }
    DIR *d = opendir("/etc/security/limits.d");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char path[PATH_MAX];
            int n = snprintf(path, sizeof(path), "/etc/security/limits.d/%s", ent->d_name);
            if (n < 0 || (size_t)n >= sizeof(path)) continue;
            if (limits_file_disables_coredumps(path)) {
                closedir(d);
                return pass_evidence("'* hard core 0' set in %s", path);
            }
        }
        closedir(d);
    }
    return fail_evidence("no '* hard core 0' limit found");
}

/* ---------- Wireless interfaces present ---------- */

static rule_result_t check_wireless_disable_interfaces(const rule_definition_t *rule) {
    (void)rule;
    DIR *d = opendir("/sys/class/net");
    if (!d) {
        return na_evidence("/sys/class/net not available");
    }
    struct dirent *ent;
    char offending[256] = "";
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        struct stat st;
        if (stat(path, &st) == 0) {
            snprintf(offending, sizeof(offending), "%s", ent->d_name);
            break;
        }
    }
    closedir(d);
    if (offending[0]) {
        return fail_evidence("wireless interface present: %s", offending);
    }
    return pass_evidence("no wireless interfaces detected");
}

/* ---------- wheel group empty ---------- */

static rule_result_t check_ensure_pam_wheel_group_empty(const rule_definition_t *rule) {
    (void)rule;
    struct group *gr = getgrnam("wheel");
    if (!gr) return pass_evidence("wheel group does not exist");
    if (!gr->gr_mem || !gr->gr_mem[0]) {
        return pass_evidence("wheel group has no members");
    }
    return fail_evidence("wheel group has members (e.g. %s)", gr->gr_mem[0]);
}

/* ---------- /etc/shadow age fields ---------- */

/* Walk interactive users via getpwent; for each, call getspnam and pass the
 * shadow entry to the supplied callback. Returns the first FAIL/ERROR, or PASS
 * if all entries comply. NOT_APPLICABLE if /etc/shadow can't be read. */
typedef rule_result_t (*shadow_check_fn)(const struct spwd *sp);

static rule_result_t for_each_interactive_shadow(shadow_check_fn fn) {
    setpwent();
    struct passwd *pw;
    bool any = false;
    bool any_shadow = false;
    while ((pw = getpwent()) != NULL) {
        if (!user_is_interactive(pw)) continue;
        any = true;
        struct spwd *sp = getspnam(pw->pw_name);
        if (!sp) continue;
        any_shadow = true;
        rule_result_t r = fn(sp);
        if (r.status == RULE_STATUS_FAIL || r.status == RULE_STATUS_ERROR) {
            endpwent();
            return r;
        }
    }
    endpwent();
    if (!any) return na_evidence("no interactive users");
    if (!any_shadow) return check_error("/etc/shadow not readable (run as root)");
    return pass_evidence("all interactive shadow entries compliant");
}

static rule_result_t shadow_check_max_life(const struct spwd *sp) {
    /* sp_max == -1 means never expire */
    if (sp->sp_max <= 0 || sp->sp_max > 365) {
        return fail_evidence("%s sp_max=%ld (expected 1-365)", sp->sp_namp, sp->sp_max);
    }
    return pass_evidence("%s sp_max=%ld", sp->sp_namp, sp->sp_max);
}

static rule_result_t shadow_check_min_life(const struct spwd *sp) {
    if (sp->sp_min < 1) {
        return fail_evidence("%s sp_min=%ld (expected >=1)", sp->sp_namp, sp->sp_min);
    }
    return pass_evidence("%s sp_min=%ld", sp->sp_namp, sp->sp_min);
}

static rule_result_t shadow_check_last_change_in_past(const struct spwd *sp) {
    long today_days = time(NULL) / (24L * 60L * 60L);
    if (sp->sp_lstchg < 0) {
        return pass_evidence("%s never changed (sp_lstchg=-1)", sp->sp_namp);
    }
    if (sp->sp_lstchg > today_days) {
        return fail_evidence("%s sp_lstchg=%ld in future (today=%ld)",
                             sp->sp_namp, sp->sp_lstchg, today_days);
    }
    return pass_evidence("%s sp_lstchg=%ld", sp->sp_namp, sp->sp_lstchg);
}

static rule_result_t check_accounts_password_set_max_life_existing(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_shadow(shadow_check_max_life);
}

static rule_result_t check_accounts_password_set_min_life_existing(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_shadow(shadow_check_min_life);
}

static rule_result_t check_accounts_password_last_change_is_in_past(const rule_definition_t *rule) {
    (void)rule; return for_each_interactive_shadow(shadow_check_last_change_in_past);
}

/* ---------- root has a hashed password ---------- */

static rule_result_t check_ensure_root_password_configured(const rule_definition_t *rule) {
    (void)rule;
    struct spwd *sp = getspnam("root");
    if (!sp) {
        if (errno == EACCES) return check_error("/etc/shadow not readable (run as root)");
        return fail_evidence("root has no /etc/shadow entry");
    }
    const char *pw = sp->sp_pwdp ? sp->sp_pwdp : "";
    if (pw[0] == '\0' || pw[0] == '!' || pw[0] == '*' || strcmp(pw, "x") == 0) {
        return fail_evidence("root password not set (sp_pwdp='%s')", pw);
    }
    if (pw[0] != '$') {
        return fail_evidence("root password not hashed (sp_pwdp='%c…')", pw[0]);
    }
    return pass_evidence("root has hashed password");
}

/* ---------- PAM faillock interval / unlock_time ---------- */

static int read_pam_faillock_param(const char *key, long *out) {
    const char *paths[] = {
        "/etc/security/faillock.conf",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/system-auth",
        NULL,
    };
    bool found = false;
    long value = LONG_MIN;
    for (size_t i = 0; paths[i]; ++i) {
        char **lines = NULL;
        size_t count = 0;
        if (load_file_lines(paths[i], &lines, &count) != 0) continue;
        for (size_t j = 0; j < count; ++j) {
            char *p = lines[j];
            while (isspace((unsigned char)*p)) p++;
            if (*p == '#' || *p == '\0') continue;
            /* faillock.conf uses `key = value`; pam.d uses `pam_faillock.so key=value` */
            const char *src = NULL;
            if (strstr(p, "pam_faillock.so") || strstr(paths[i], "faillock.conf")) {
                src = strstr(p, key);
            }
            if (!src) continue;
            const char *after = src + strlen(key);
            while (*after && (isspace((unsigned char)*after) || *after == '=')) after++;
            char *endp = NULL;
            errno = 0;
            long parsed = strtol(after, &endp, 10);
            if (endp != after && errno == 0) {
                value = parsed;
                found = true;
                break;
            }
        }
        free_lines(lines, count);
        if (found) break;
    }
    if (!found) return -1;
    *out = value;
    return 0;
}

static rule_result_t check_accounts_passwords_pam_faillock_interval(const rule_definition_t *rule) {
    (void)rule;
    long v;
    if (read_pam_faillock_param("fail_interval", &v) != 0
        && read_pam_faillock_param("interval", &v) != 0) {
        return fail_evidence("pam_faillock interval not configured");
    }
    if (v >= 900) return pass_evidence("faillock interval=%ld", v);
    return fail_evidence("faillock interval=%ld (expected >=900)", v);
}

static rule_result_t check_accounts_passwords_pam_faillock_unlock_time(const rule_definition_t *rule) {
    (void)rule;
    long v;
    if (read_pam_faillock_param("unlock_time", &v) != 0) {
        return fail_evidence("pam_faillock unlock_time not configured");
    }
    if (v >= 600) return pass_evidence("faillock unlock_time=%ld", v);
    return fail_evidence("faillock unlock_time=%ld (expected >=600)", v);
}

/* ---------- pam_wheel for su ---------- */

static rule_result_t check_use_pam_wheel_group_for_su(const rule_definition_t *rule) {
    (void)rule;
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines("/etc/pam.d/su", &lines, &count) != 0) {
        return check_error("unable to read /etc/pam.d/su");
    }
    bool found = false;
    bool has_group = false;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (!strstr(p, "pam_wheel.so")) continue;
        /* Must be auth required (or auth sufficient), not commented */
        if (!strstr(p, "auth")) continue;
        found = true;
        if (strstr(p, "group=")) has_group = true;
        if (found && has_group) break;
    }
    free_lines(lines, count);
    if (!found) return fail_evidence("pam_wheel.so not enabled in /etc/pam.d/su");
    if (!has_group) return fail_evidence("pam_wheel.so in /etc/pam.d/su lacks group= parameter");
    return pass_evidence("pam_wheel.so enabled with group= in /etc/pam.d/su");
}

/* ---------- AppArmor profile states ---------- */

static rule_result_t check_all_apparmor_profiles_in_enforce_complain_mode(const rule_definition_t *rule) {
    (void)rule;
    const char *path = "/sys/kernel/security/apparmor/profiles";
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(path, &lines, &count) != 0) {
        return na_evidence("%s not available", path);
    }
    if (count == 0) {
        free_lines(lines, count);
        return na_evidence("no AppArmor profiles loaded");
    }
    char offending[256] = "";
    for (size_t i = 0; i < count; ++i) {
        const char *line = lines[i];
        if (strstr(line, "(enforce)") == NULL && strstr(line, "(complain)") == NULL) {
            snprintf(offending, sizeof(offending), "%s", line);
            break;
        }
    }
    free_lines(lines, count);
    if (offending[0]) {
        return fail_evidence("profile not in enforce/complain: %s", offending);
    }
    return pass_evidence("all AppArmor profiles in enforce or complain mode");
}

/* ---------- GRUB: AppArmor cmdline + bootloader password ---------- */

static rule_result_t check_grub2_enable_apparmor(const rule_definition_t *rule) {
    (void)rule;
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines("/etc/default/grub", &lines, &count) != 0) {
        return check_error("unable to read /etc/default/grub");
    }
    bool found_apparmor = false;
    bool found_security = false;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (strncmp(p, "GRUB_CMDLINE_LINUX", 18) != 0) continue;
        if (strstr(p, "apparmor=1"))          found_apparmor = true;
        if (strstr(p, "security=apparmor"))   found_security = true;
    }
    free_lines(lines, count);
    if (found_apparmor && found_security) {
        return pass_evidence("GRUB cmdline enables apparmor");
    }
    return fail_evidence("GRUB cmdline missing apparmor=1 and/or security=apparmor");
}

static rule_result_t check_grub_password_in_path(const char *grub_cfg) {
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(grub_cfg, &lines, &count) != 0) {
        return na_evidence("%s not found", grub_cfg);
    }
    bool has_superusers = false;
    bool has_password = false;
    for (size_t i = 0; i < count; ++i) {
        const char *line = lines[i];
        if (strstr(line, "set superusers=")) has_superusers = true;
        if (strstr(line, "password_pbkdf2") || strstr(line, "password ")) has_password = true;
    }
    free_lines(lines, count);
    if (has_superusers && has_password) {
        return pass_evidence("GRUB superusers + password configured in %s", grub_cfg);
    }
    return fail_evidence("GRUB password not configured in %s", grub_cfg);
}

static rule_result_t check_grub2_password(const rule_definition_t *rule) {
    (void)rule;
    const char *paths[] = { "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", NULL };
    for (size_t i = 0; paths[i]; ++i) {
        struct stat st;
        if (stat(paths[i], &st) == 0) return check_grub_password_in_path(paths[i]);
    }
    return na_evidence("BIOS grub.cfg not present");
}

static rule_result_t check_grub2_uefi_password(const rule_definition_t *rule) {
    (void)rule;
    const char *paths[] = {
        "/boot/efi/EFI/debian/grub.cfg",
        "/boot/efi/EFI/ubuntu/grub.cfg",
        "/boot/efi/EFI/redhat/grub.cfg",
        NULL,
    };
    for (size_t i = 0; paths[i]; ++i) {
        struct stat st;
        if (stat(paths[i], &st) == 0) return check_grub_password_in_path(paths[i]);
    }
    return na_evidence("UEFI grub.cfg not present");
}

/* ---------- root PATH ---------- */

static rule_result_t check_root_path_no_dot(const rule_definition_t *rule) {
    (void)rule;
    const char *paths[] = { "/root/.bashrc", "/root/.profile", "/root/.bash_profile", NULL };
    for (size_t i = 0; paths[i]; ++i) {
        char **lines = NULL;
        size_t count = 0;
        if (load_file_lines(paths[i], &lines, &count) != 0) continue;
        for (size_t j = 0; j < count; ++j) {
            char *p = lines[j];
            while (isspace((unsigned char)*p)) p++;
            if (*p == '#' || *p == '\0') continue;
            const char *eq = strstr(p, "PATH=");
            if (!eq) continue;
            const char *val = eq + 5;
            /* Strip quotes if present */
            if (*val == '"' || *val == '\'') val++;
            /* Walk colon-separated dirs */
            const char *cursor = val;
            while (*cursor && *cursor != '"' && *cursor != '\'' && *cursor != ' ' && *cursor != '\t') {
                const char *colon = strchr(cursor, ':');
                size_t len = colon ? (size_t)(colon - cursor) : strlen(cursor);
                if (len == 0 || (len == 1 && cursor[0] == '.')) {
                    rule_result_t r = fail_evidence("root PATH contains '.' or empty entry in %s", paths[i]);
                    free_lines(lines, count);
                    return r;
                }
                cursor += len;
                if (!*cursor || *cursor != ':') break;
                cursor++;
            }
        }
        free_lines(lines, count);
    }
    return pass_evidence("root PATH contains no '.' or empty entries");
}

/* ---------- Composite: interactive-user umask ---------- */

static rule_result_t check_accounts_umask_interactive_users(const rule_definition_t *rule) {
    (void)rule;
    long v;
    if (read_login_defs_long("UMASK", &v) != 0) {
        return fail_evidence("UMASK not set in /etc/login.defs");
    }
    if (v != 027 && v != 077) {
        return fail_evidence("/etc/login.defs UMASK=%03lo (expected 027 or 077)", v);
    }
    rule_result_t r = check_umask_in_shell_file("/etc/profile");
    if (r.status == RULE_STATUS_PASS) {
        return pass_evidence("interactive umask 027/077 enforced by login.defs and /etc/profile");
    }
    return r;
}

/* ---------- /etc/default/useradd INACTIVE ---------- */

static rule_result_t check_account_disable_post_pw_expiration(const rule_definition_t *rule) {
    (void)rule;
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines("/etc/default/useradd", &lines, &count) != 0) {
        return check_error("unable to read /etc/default/useradd");
    }
    long inactive = LONG_MIN;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (strncmp(p, "INACTIVE", 8) != 0) continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        char *val = eq + 1;
        while (*val && isspace((unsigned char)*val)) val++;
        char *endp = NULL;
        errno = 0;
        long parsed = strtol(val, &endp, 10);
        if (endp != val && errno == 0) inactive = parsed;
    }
    free_lines(lines, count);
    if (inactive == LONG_MIN) {
        return fail_evidence("INACTIVE not set in /etc/default/useradd");
    }
    if (inactive >= 1 && inactive <= 30) {
        return pass_evidence("INACTIVE=%ld in /etc/default/useradd", inactive);
    }
    return fail_evidence("INACTIVE=%ld (expected 1-30)", inactive);
}

/* ---------- rsyslog nolisten / remote loghost ---------- */

static bool rsyslog_loads_listener(const char *path) {
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(path, &lines, &count) != 0) return false;
    bool listener = false;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (strstr(p, "imtcp") || strstr(p, "imudp")
            || strstr(p, "ModLoad imtcp") || strstr(p, "ModLoad imudp")) {
            listener = true;
            break;
        }
    }
    free_lines(lines, count);
    return listener;
}

static rule_result_t check_rsyslog_nolisten(const rule_definition_t *rule) {
    (void)rule;
    if (rsyslog_loads_listener("/etc/rsyslog.conf")) {
        return fail_evidence("rsyslog.conf loads imtcp/imudp listener");
    }
    DIR *d = opendir("/etc/rsyslog.d");
    if (d) {
        struct dirent *ent;
        char offending[PATH_MAX] = "";
        while ((ent = readdir(d)) != NULL) {
            size_t nlen = strlen(ent->d_name);
            if (nlen <= 5 || strcmp(ent->d_name + nlen - 5, ".conf") != 0) continue;
            char path[PATH_MAX];
            int n = snprintf(path, sizeof(path), "/etc/rsyslog.d/%s", ent->d_name);
            if (n < 0 || (size_t)n >= sizeof(path)) continue;
            if (rsyslog_loads_listener(path)) {
                snprintf(offending, sizeof(offending), "%s", path);
                break;
            }
        }
        closedir(d);
        if (offending[0]) {
            return fail_evidence("%s loads imtcp/imudp listener", offending);
        }
    }
    return pass_evidence("no rsyslog network listener configured");
}

static bool rsyslog_forwards(const char *path) {
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(path, &lines, &count) != 0) return false;
    bool found = false;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        /* @host = UDP forward, @@host = TCP forward; either anywhere on a syslog rule line. */
        if (strstr(p, "@@") || strchr(p, '@')) {
            /* Avoid hits in module/comment lines: require it after whitespace. */
            char *at = strchr(p, '@');
            if (at && (at == p || isspace((unsigned char)at[-1]))) {
                found = true;
                break;
            }
        }
    }
    free_lines(lines, count);
    return found;
}

/* ---------- Firewall default policies (iptables, ip6tables, nftables, ufw) ---------- */

static const char *first_executable(const char *const *candidates) {
    for (size_t i = 0; candidates[i]; ++i) {
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    }
    return NULL;
}

static int popen_capture(const char *cmd, char *out, size_t out_size) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    out[0] = '\0';
    char *p = out;
    size_t remaining = (out_size > 0) ? out_size - 1 : 0;
    while (remaining > 0) {
        if (fgets(p, (int)remaining + 1, fp) == NULL) break;
        size_t len = strlen(p);
        if (len == 0) break;
        p += len;
        remaining -= len;
    }
    return pclose(fp);
}

static rule_result_t check_xtables_input_default(const char *const *bins, const char *family) {
    const char *bin = first_executable(bins);
    if (!bin) return na_evidence("%s binary not present", family);
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s -L INPUT -n 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return check_error("command too long");
    char out[4096];
    if (popen_capture(cmd, out, sizeof(out)) == -1) {
        return check_error("popen failed");
    }
    if (out[0] == '\0') {
        return check_error("no output from iptables (run as root)");
    }
    if (strstr(out, "policy DROP") || strstr(out, "policy REJECT")) {
        return pass_evidence("%s INPUT default policy is DROP/REJECT", family);
    }
    if (strstr(out, "policy ACCEPT")) {
        return fail_evidence("%s INPUT default policy is ACCEPT", family);
    }
    return check_error("could not determine INPUT policy");
}

static rule_result_t check_set_iptables_default_rule(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/iptables", "/sbin/iptables", NULL };
    return check_xtables_input_default(bins, "iptables");
}

static rule_result_t check_set_ip6tables_default_rule(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/ip6tables", "/sbin/ip6tables", NULL };
    return check_xtables_input_default(bins, "ip6tables");
}

static rule_result_t check_nftables_ensure_default_deny_policy(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", NULL };
    const char *bin = first_executable(bins);
    if (!bin) return na_evidence("nft binary not present");
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s list ruleset 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return check_error("command too long");
    char out[65536];
    if (popen_capture(cmd, out, sizeof(out)) == -1) {
        return check_error("popen failed");
    }
    if (out[0] == '\0') {
        return fail_evidence("no nftables ruleset present");
    }
    /* Find each "hook input" line and confirm the chain's policy is drop. */
    bool saw_input_hook = false;
    bool saw_permissive = false;
    char *saveptr = NULL;
    char *line;
    for (line = strtok_r(out, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
        if (!strstr(line, "hook input")) continue;
        saw_input_hook = true;
        if (strstr(line, "policy drop") == NULL) {
            saw_permissive = true;
            break;
        }
    }
    if (!saw_input_hook) {
        return fail_evidence("no nftables chain with hook input found");
    }
    if (saw_permissive) {
        return fail_evidence("nftables input chain not policy drop");
    }
    return pass_evidence("all nftables input chains policy drop");
}

static rule_result_t check_set_ufw_default_rule(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw", NULL };
    const char *bin = first_executable(bins);
    if (!bin) return na_evidence("ufw binary not present");
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s status verbose 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return check_error("command too long");
    char out[8192];
    if (popen_capture(cmd, out, sizeof(out)) == -1) {
        return check_error("popen failed");
    }
    if (out[0] == '\0') {
        return check_error("no output from ufw (run as root)");
    }
    if (strstr(out, "Status: inactive")) {
        return fail_evidence("ufw status is inactive");
    }
    if (strstr(out, "Default: deny (incoming)") || strstr(out, "Default: reject (incoming)")) {
        return pass_evidence("ufw default incoming policy is deny/reject");
    }
    return fail_evidence("ufw default incoming policy is not deny/reject");
}

/* ---------- /var/log permission walk (recursive, mode <= 0640 for files, 0750 for dirs) ---------- */

static rule_result_t walk_var_log_permissions(const char *root, int depth) {
    if (depth > 8) return pass_evidence("recursion limit reached");
    DIR *d = opendir(root);
    if (!d) {
        if (errno == ENOENT) return na_evidence("%s does not exist", root);
        return check_error("unable to opendir /var/log");
    }
    struct dirent *ent;
    rule_result_t result = pass_evidence("%s tree permissions compliant", root);
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.'
            && (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", root, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        mode_t actual = st.st_mode & 07777;
        if (S_ISDIR(st.st_mode)) {
            if ((actual & ~(mode_t)0750) != 0) {
                result = fail_evidence("dir %s mode=%04o (expected <= 0750)", path, actual);
                break;
            }
            rule_result_t sub = walk_var_log_permissions(path, depth + 1);
            if (sub.status == RULE_STATUS_FAIL || sub.status == RULE_STATUS_ERROR) {
                result = sub;
                break;
            }
        } else if (S_ISREG(st.st_mode)) {
            if ((actual & ~(mode_t)0640) != 0) {
                result = fail_evidence("file %s mode=%04o (expected <= 0640)", path, actual);
                break;
            }
        }
    }
    closedir(d);
    return result;
}

static rule_result_t check_permissions_local_var_log(const rule_definition_t *rule) {
    (void)rule;
    return walk_var_log_permissions("/var/log", 0);
}

static rule_result_t check_rsyslog_remote_loghost(const rule_definition_t *rule) {
    (void)rule;
    if (rsyslog_forwards("/etc/rsyslog.conf")) {
        return pass_evidence("rsyslog.conf forwards to remote loghost");
    }
    DIR *d = opendir("/etc/rsyslog.d");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            size_t nlen = strlen(ent->d_name);
            if (nlen <= 5 || strcmp(ent->d_name + nlen - 5, ".conf") != 0) continue;
            char path[PATH_MAX];
            int n = snprintf(path, sizeof(path), "/etc/rsyslog.d/%s", ent->d_name);
            if (n < 0 || (size_t)n >= sizeof(path)) continue;
            if (rsyslog_forwards(path)) {
                closedir(d);
                return pass_evidence("%s forwards to remote loghost", path);
            }
        }
        closedir(d);
    }
    return fail_evidence("no rsyslog remote-forward rule found");
}

/* ---------- Firewall loopback traffic rules ---------- */

static rule_result_t check_xtables_loopback(const char *const *bins, const char *family) {
    const char *bin = first_executable(bins);
    if (!bin) return na_evidence("%s binary not present", family);
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s -L INPUT -n -v 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return check_error("command too long");
    char out[16384];
    if (popen_capture(cmd, out, sizeof(out)) == -1) {
        return check_error("popen failed");
    }
    if (out[0] == '\0') {
        return check_error("no output from iptables (run as root)");
    }
    /* Expect an INPUT ACCEPT rule with in iface "lo". iptables -v output
     * prints the iface column as the source iface (5th column). We match
     * the substring " lo " (surrounded by whitespace) on an ACCEPT line. */
    char *saveptr = NULL;
    bool found = false;
    char *line;
    for (line = strtok_r(out, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
        if (!strstr(line, "ACCEPT")) continue;
        if (strstr(line, " lo ")) { found = true; break; }
    }
    if (found) {
        return pass_evidence("%s INPUT has ACCEPT rule for lo", family);
    }
    return fail_evidence("%s INPUT has no ACCEPT rule for loopback (lo)", family);
}

static rule_result_t check_set_loopback_traffic(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/iptables", "/sbin/iptables", NULL };
    return check_xtables_loopback(bins, "iptables");
}

static rule_result_t check_set_ipv6_loopback_traffic(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/ip6tables", "/sbin/ip6tables", NULL };
    return check_xtables_loopback(bins, "ip6tables");
}

static rule_result_t check_set_ufw_loopback_traffic(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw", NULL };
    const char *bin = first_executable(bins);
    if (!bin) return na_evidence("ufw binary not present");
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s status verbose 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return check_error("command too long");
    char out[16384];
    if (popen_capture(cmd, out, sizeof(out)) == -1) {
        return check_error("popen failed");
    }
    /* ufw allow on lo is implicit when status is active; explicit "allow in on lo"
     * may also appear. Treat status=active with no deny-lo rule as pass. */
    if (strstr(out, "Status: inactive")) {
        return fail_evidence("ufw inactive — loopback not protected");
    }
    if (strstr(out, "Anywhere on lo") || strstr(out, "ALLOW IN") || strstr(out, "Status: active")) {
        return pass_evidence("ufw allows loopback (implicit when active)");
    }
    return fail_evidence("ufw status did not confirm loopback allow");
}

static rule_result_t check_set_nftables_loopback_traffic(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", NULL };
    const char *bin = first_executable(bins);
    if (!bin) return na_evidence("nft binary not present");
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s list ruleset 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return check_error("command too long");
    char out[65536];
    if (popen_capture(cmd, out, sizeof(out)) == -1) {
        return check_error("popen failed");
    }
    if (out[0] == '\0') {
        return fail_evidence("no nftables ruleset present");
    }
    /* Look for "iif lo accept" or "iif \"lo\" accept" on an input chain. */
    if (strstr(out, "iif lo accept") || strstr(out, "iif \"lo\" accept")) {
        return pass_evidence("nftables accepts traffic on loopback");
    }
    return fail_evidence("nftables ruleset has no 'iif lo accept' rule");
}

/* ---------- nftables structural ---------- */

static int nft_list_ruleset(char *out, size_t out_size) {
    static const char *bins[] = { "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", NULL };
    const char *bin = first_executable(bins);
    if (!bin) return -1;
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s list ruleset 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return -1;
    return popen_capture(cmd, out, out_size);
}

static rule_result_t check_set_nftables_table(const rule_definition_t *rule) {
    (void)rule;
    char out[65536];
    if (nft_list_ruleset(out, sizeof(out)) == -1) {
        return na_evidence("nft binary not present");
    }
    /* Any line starting with "table" indicates a defined table. */
    char *saveptr = NULL;
    char *line;
    for (line = strtok_r(out, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
        const char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (strncmp(p, "table ", 6) == 0) {
            return pass_evidence("nftables table declared: %s", p);
        }
    }
    return fail_evidence("no nftables table found in ruleset");
}

static rule_result_t check_set_nftables_base_chain(const rule_definition_t *rule) {
    (void)rule;
    char out[65536];
    if (nft_list_ruleset(out, sizeof(out)) == -1) {
        return na_evidence("nft binary not present");
    }
    if (strstr(out, "type filter hook input")) {
        return pass_evidence("nftables base chain with hook input present");
    }
    return fail_evidence("no base chain with 'type filter hook input' found");
}

static rule_result_t check_nftables_rules_permanent(const rule_definition_t *rule) {
    (void)rule;
    /* On Debian/Ubuntu, nftables persistence is provided by either
     * /etc/nftables.conf (loaded by nftables.service) or a snippet in
     * /etc/nftables.d/. We accept either: file present AND non-empty,
     * AND nftables.service is enabled. */
    struct stat st;
    bool conf_present = false;
    if (stat("/etc/nftables.conf", &st) == 0 && st.st_size > 0) conf_present = true;
    if (!conf_present) {
        DIR *d = opendir("/etc/nftables.d");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                conf_present = true;
                break;
            }
            closedir(d);
        }
    }
    if (!conf_present) {
        return fail_evidence("no /etc/nftables.conf or /etc/nftables.d entries");
    }
    char unit_state[64];
    if (systemctl_query("is-enabled", "nftables.service", unit_state, sizeof(unit_state)) != 0) {
        return pass_evidence("nftables config present (systemctl unavailable)");
    }
    if (unit_state[0] == '\0' || strcmp(unit_state, "not-found") == 0) {
        return fail_evidence("nftables config present but nftables.service is not installed");
    }
    if (strcmp(unit_state, "enabled") == 0 || strcmp(unit_state, "static") == 0) {
        return pass_evidence("nftables config present and unit %s", unit_state);
    }
    return fail_evidence("nftables config present but unit is %s", unit_state);
}

/* ---------- Listening ports cross-checked against firewall ---------- */

/* Collect listening TCP ports from `ss -lnt`. Output looks like:
 *   State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
 *   LISTEN 0       128     0.0.0.0:22          0.0.0.0:*
 * We extract the port from the Local Address column. v6 entries appear as
 * `[::]:8000`, which we strip the brackets from.
 */
static int collect_listening_tcp_ports(int *ports, size_t cap, size_t *count_out, bool ipv6) {
    static const char *bins[] = { "/usr/bin/ss", "/bin/ss", "/usr/sbin/ss", "/sbin/ss", NULL };
    const char *bin = first_executable(bins);
    if (!bin) return -1;
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s -lntH 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return -1;
    char out[32768];
    if (popen_capture(cmd, out, sizeof(out)) == -1) return -1;
    size_t count = 0;
    char *saveptr = NULL;
    char *line;
    for (line = strtok_r(out, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
        /* Skip header */
        if (strncmp(line, "State", 5) == 0) continue;
        /* Tokenize on whitespace, take the 4th column (Local Address:Port) */
        char *tok_save = NULL;
        char *t = strtok_r(line, " \t", &tok_save);
        int col = 0;
        char *local = NULL;
        while (t) {
            col++;
            if (col == 4) { local = t; break; }
            t = strtok_r(NULL, " \t", &tok_save);
        }
        if (!local) continue;
        bool is_v6 = (local[0] == '[');
        if (is_v6 != ipv6) continue;
        /* Find the last ':' before the port */
        char *colon = strrchr(local, ':');
        if (!colon) continue;
        long port = strtol(colon + 1, NULL, 10);
        if (port <= 0 || port > 65535) continue;
        if (count < cap) {
            ports[count++] = (int)port;
        }
    }
    *count_out = count;
    return 0;
}

static rule_result_t check_xtables_ports_have_rules(const char *const *bins, const char *family, bool ipv6) {
    const char *bin = first_executable(bins);
    if (!bin) return na_evidence("%s binary not present", family);

    int ports[256];
    size_t port_count = 0;
    if (collect_listening_tcp_ports(ports, sizeof(ports) / sizeof(ports[0]), &port_count, ipv6) != 0) {
        return check_error("unable to enumerate listening ports (ss missing?)");
    }
    if (port_count == 0) {
        return pass_evidence("no listening %s ports to verify", family);
    }

    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s -S 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return check_error("command too long");
    char out[65536];
    if (popen_capture(cmd, out, sizeof(out)) == -1) {
        return check_error("popen failed");
    }
    if (out[0] == '\0') {
        return check_error("no output from %s -S (run as root)");
    }

    /* For each port, check if there's a rule containing "dport <port>" or "--dport <port>". */
    for (size_t i = 0; i < port_count; ++i) {
        char needle[32];
        snprintf(needle, sizeof(needle), "dport %d", ports[i]);
        if (!strstr(out, needle)) {
            char alt[32];
            snprintf(alt, sizeof(alt), "--dport %d", ports[i]);
            if (!strstr(out, alt)) {
                return fail_evidence("%s port %d has no firewall rule", family, ports[i]);
            }
        }
    }
    return pass_evidence("all %zu listening %s port(s) covered by firewall", port_count, family);
}

static rule_result_t check_iptables_rules_for_open_ports(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/iptables", "/sbin/iptables", NULL };
    return check_xtables_ports_have_rules(bins, "iptables", false);
}

static rule_result_t check_ip6tables_rules_for_open_ports(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/ip6tables", "/sbin/ip6tables", NULL };
    return check_xtables_ports_have_rules(bins, "ip6tables", true);
}

static rule_result_t check_ufw_rules_for_open_ports(const rule_definition_t *rule) {
    (void)rule;
    static const char *bins[] = { "/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw", NULL };
    const char *bin = first_executable(bins);
    if (!bin) return na_evidence("ufw binary not present");

    int ports[256];
    size_t port_count = 0;
    if (collect_listening_tcp_ports(ports, sizeof(ports) / sizeof(ports[0]), &port_count, false) != 0) {
        return check_error("unable to enumerate listening ports");
    }
    if (port_count == 0) {
        return pass_evidence("no listening ports to verify");
    }

    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "%s status 2>/dev/null", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return check_error("command too long");
    char out[16384];
    if (popen_capture(cmd, out, sizeof(out)) == -1) return check_error("popen failed");
    if (strstr(out, "Status: inactive")) {
        return fail_evidence("ufw inactive — no rules enforced");
    }

    for (size_t i = 0; i < port_count; ++i) {
        /* ufw status shows rules like "22/tcp ALLOW Anywhere" */
        char needle[32];
        snprintf(needle, sizeof(needle), "%d/tcp", ports[i]);
        if (!strstr(out, needle)) {
            return fail_evidence("ufw has no rule for listening port %d/tcp", ports[i]);
        }
    }
    return pass_evidence("all %zu listening port(s) covered by ufw", port_count);
}

/* ---------- Filesystem walks: world-writable, unowned, ungroupowned ----------
 *
 * One nftw-based walker visits the filesystem rooted at "/", skips
 * pseudo-filesystems (/proc, /sys, /dev, /run) and network mounts (nfs,
 * fuse, cifs), and for each regular file or directory invokes the supplied
 * predicate. The walk stops at the first FAIL or after a hard cap on visited
 * inodes to keep audit time predictable.
 */

#define FS_WALK_MAX_INODES 250000

typedef enum {
    FS_FAIL_NONE,
    FS_FAIL_WORLD_WRITABLE,
    FS_FAIL_UNOWNED_USER,
    FS_FAIL_UNOWNED_GROUP,
} fs_fail_kind_t;

typedef struct {
    fs_fail_kind_t fail_kind;
    char offending_path[PATH_MAX];
    size_t visited;
    fs_fail_kind_t target;
} fs_walk_ctx_t;

static fs_walk_ctx_t g_fs_ctx;

static bool path_is_skipped(const char *path) {
    /* Skip kernel and runtime pseudo-filesystems and obvious noise. */
    static const char *prefixes[] = {
        "/proc/", "/sys/", "/dev/", "/run/", "/var/run/",
        "/snap/", "/var/lib/docker/", "/var/lib/containers/",
        "/var/lib/lxd/", "/var/lib/lxc/",
        NULL,
    };
    for (size_t i = 0; prefixes[i]; ++i) {
        size_t plen = strlen(prefixes[i]);
        if (strncmp(path, prefixes[i], plen) == 0) return true;
    }
    return false;
}

static int fs_walk_visitor(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    if (path_is_skipped(fpath)) return FTW_SKIP_SUBTREE;
    if (g_fs_ctx.visited++ > FS_WALK_MAX_INODES) return FTW_STOP;

    if (typeflag != FTW_F && typeflag != FTW_D) return FTW_CONTINUE;

    switch (g_fs_ctx.target) {
        case FS_FAIL_WORLD_WRITABLE:
            /* World-writable AND not sticky (sticky on dirs like /tmp is fine).
             * Symlinks excluded — they're never traversed by nftw without FOLLOW. */
            if ((sb->st_mode & S_IWOTH) && !(sb->st_mode & S_ISVTX)) {
                g_fs_ctx.fail_kind = FS_FAIL_WORLD_WRITABLE;
                snprintf(g_fs_ctx.offending_path, sizeof(g_fs_ctx.offending_path),
                         "%s", fpath);
                return FTW_STOP;
            }
            break;
        case FS_FAIL_UNOWNED_USER:
            if (getpwuid(sb->st_uid) == NULL) {
                g_fs_ctx.fail_kind = FS_FAIL_UNOWNED_USER;
                snprintf(g_fs_ctx.offending_path, sizeof(g_fs_ctx.offending_path),
                         "%s (uid=%u)", fpath, (unsigned)sb->st_uid);
                return FTW_STOP;
            }
            break;
        case FS_FAIL_UNOWNED_GROUP:
            if (getgrgid(sb->st_gid) == NULL) {
                g_fs_ctx.fail_kind = FS_FAIL_UNOWNED_GROUP;
                snprintf(g_fs_ctx.offending_path, sizeof(g_fs_ctx.offending_path),
                         "%s (gid=%u)", fpath, (unsigned)sb->st_gid);
                return FTW_STOP;
            }
            break;
        case FS_FAIL_NONE:
            break;
    }
    return FTW_CONTINUE;
}

static rule_result_t run_fs_walk(fs_fail_kind_t target, const char *pass_msg, const char *fail_label) {
    g_fs_ctx.fail_kind = FS_FAIL_NONE;
    g_fs_ctx.offending_path[0] = '\0';
    g_fs_ctx.visited = 0;
    g_fs_ctx.target = target;

    /* FTW_PHYS = don't follow symlinks. FTW_MOUNT = don't cross mountpoints
     * (skips network mounts, /proc submounts, etc. without us having to
     * enumerate them). FTW_ACTIONRETVAL = honor FTW_SKIP_SUBTREE / FTW_STOP. */
    int flags = FTW_PHYS | FTW_MOUNT | FTW_ACTIONRETVAL;
    int rc = nftw("/", fs_walk_visitor, 64, flags);
    if (rc < 0) return check_error("nftw walk failed");

    if (g_fs_ctx.visited > FS_WALK_MAX_INODES) {
        return na_evidence("walk exceeded %d inodes — partial scan only", FS_WALK_MAX_INODES);
    }
    if (g_fs_ctx.fail_kind != FS_FAIL_NONE) {
        return fail_evidence("%s: %s", fail_label, g_fs_ctx.offending_path);
    }
    return pass_evidence("%s (scanned %zu paths)", pass_msg, g_fs_ctx.visited);
}

static rule_result_t check_file_permissions_unauthorized_world_writable(const rule_definition_t *rule) {
    (void)rule;
    return run_fs_walk(FS_FAIL_WORLD_WRITABLE,
                       "no unauthorized world-writable files",
                       "world-writable without sticky");
}

static rule_result_t check_no_files_unowned_by_user(const rule_definition_t *rule) {
    (void)rule;
    return run_fs_walk(FS_FAIL_UNOWNED_USER,
                       "every file owned by a valid user",
                       "file with unknown user");
}

static rule_result_t check_file_permissions_ungroupowned(const rule_definition_t *rule) {
    (void)rule;
    return run_fs_walk(FS_FAIL_UNOWNED_GROUP,
                       "every file owned by a valid group",
                       "file with unknown group");
}

/* ---------- PATH directory writability ---------- */

static bool dir_is_world_or_group_writable(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return false;
    if (!S_ISDIR(st.st_mode)) return false;
    return (st.st_mode & (S_IWGRP | S_IWOTH)) != 0;
}

/* Extract PATH= entries from a shell rc file and return the first unsafe
 * directory found, or NULL if all entries are safe. Caller-owned static
 * buffer reused on each call. */
static const char *find_unsafe_path_dir_in_shell_file(const char *file) {
    static char offender[PATH_MAX];
    offender[0] = '\0';
    char **lines = NULL;
    size_t count = 0;
    if (load_file_lines(file, &lines, &count) != 0) return NULL;
    for (size_t i = 0; i < count; ++i) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        const char *eq = strstr(p, "PATH=");
        if (!eq) continue;
        const char *val = eq + 5;
        if (*val == '"' || *val == '\'') val++;
        const char *cursor = val;
        while (*cursor && *cursor != '"' && *cursor != '\'' && *cursor != ' ' && *cursor != '\t') {
            const char *colon = strchr(cursor, ':');
            size_t len = colon ? (size_t)(colon - cursor) : strlen(cursor);
            if (len > 0 && len < sizeof(offender)) {
                char dir[PATH_MAX];
                memcpy(dir, cursor, len);
                dir[len] = '\0';
                if (dir[0] == '/' && dir_is_world_or_group_writable(dir)) {
                    snprintf(offender, sizeof(offender), "%.512s in %.512s", dir, file);
                    free_lines(lines, count);
                    return offender;
                }
            }
            cursor += len;
            if (!*cursor || *cursor != ':') break;
            cursor++;
        }
    }
    free_lines(lines, count);
    return NULL;
}

static rule_result_t check_accounts_root_path_dirs_no_write(const rule_definition_t *rule) {
    (void)rule;
    const char *paths[] = { "/root/.bashrc", "/root/.profile", "/root/.bash_profile", NULL };
    for (size_t i = 0; paths[i]; ++i) {
        const char *off = find_unsafe_path_dir_in_shell_file(paths[i]);
        if (off) return fail_evidence("root PATH entry is writable: %s", off);
    }
    return pass_evidence("root PATH contains no writable directories");
}

static rule_result_t per_user_dot_no_writable_path(const struct passwd *pw) {
    if (!pw->pw_dir || !*pw->pw_dir) return pass_evidence("%s no home", pw->pw_name);
    const char *dotfiles[] = {
        ".bashrc", ".bash_profile", ".bash_login", ".profile",
        ".zshrc", ".cshrc", ".tcshrc", ".login", ".kshrc", NULL
    };
    for (size_t i = 0; dotfiles[i]; ++i) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", pw->pw_dir, dotfiles[i]);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        const char *off = find_unsafe_path_dir_in_shell_file(path);
        if (off) return fail_evidence("user %s PATH entry writable: %s", pw->pw_name, off);
    }
    return pass_evidence("user %s init dotfiles have safe PATH entries", pw->pw_name);
}

static rule_result_t check_accounts_user_dot_no_world_writable_programs(const rule_definition_t *rule) {
    (void)rule;
    return for_each_interactive_user(per_user_dot_no_writable_path);
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

    /* File owner / group / permissions on the password & shadow databases and their backups */
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_etc_passwd", check_file_owner_etc_passwd);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_etc_group", check_file_owner_etc_group);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_etc_shadow", check_file_owner_etc_shadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_etc_gshadow", check_file_owner_etc_gshadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_backup_etc_passwd", check_file_owner_backup_etc_passwd);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_backup_etc_group", check_file_owner_backup_etc_group);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_backup_etc_shadow", check_file_owner_backup_etc_shadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_backup_etc_gshadow", check_file_owner_backup_etc_gshadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd", check_file_groupowner_etc_passwd);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_etc_group", check_file_groupowner_etc_group);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_etc_shadow", check_file_groupowner_etc_shadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_etc_gshadow", check_file_groupowner_etc_gshadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_passwd", check_file_groupowner_backup_etc_passwd);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_group", check_file_groupowner_backup_etc_group);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_shadow", check_file_groupowner_backup_etc_shadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_gshadow", check_file_groupowner_backup_etc_gshadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd", check_file_permissions_etc_passwd);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_etc_group", check_file_permissions_etc_group);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_etc_shadow", check_file_permissions_etc_shadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_etc_gshadow", check_file_permissions_etc_gshadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_passwd", check_file_permissions_backup_etc_passwd);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_group", check_file_permissions_backup_etc_group);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_shadow", check_file_permissions_backup_etc_shadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_gshadow", check_file_permissions_backup_etc_gshadow);

    /* Crontab and the per-frequency cron directories */
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_crontab", check_file_owner_crontab);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_cron_d", check_file_owner_cron_d);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_cron_daily", check_file_owner_cron_daily);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_cron_hourly", check_file_owner_cron_hourly);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_cron_monthly", check_file_owner_cron_monthly);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_cron_weekly", check_file_owner_cron_weekly);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_crontab", check_file_groupowner_crontab);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_cron_d", check_file_groupowner_cron_d);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_cron_daily", check_file_groupowner_cron_daily);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_cron_hourly", check_file_groupowner_cron_hourly);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_cron_monthly", check_file_groupowner_cron_monthly);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupowner_cron_weekly", check_file_groupowner_cron_weekly);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_crontab", check_file_permissions_crontab);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_cron_d", check_file_permissions_cron_d);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_cron_daily", check_file_permissions_cron_daily);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_cron_hourly", check_file_permissions_cron_hourly);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_cron_monthly", check_file_permissions_cron_monthly);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_cron_weekly", check_file_permissions_cron_weekly);

    /* sysctl: IPv4/IPv6 network hardening + kernel ASLR + suid dumpable */
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_ra", check_sysctl_net_ipv6_conf_all_accept_ra);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_redirects", check_sysctl_net_ipv6_conf_all_accept_redirects);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_source_route", check_sysctl_net_ipv6_conf_all_accept_source_route);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_forwarding", check_sysctl_net_ipv6_conf_all_forwarding);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_ra", check_sysctl_net_ipv6_conf_default_accept_ra);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_redirects", check_sysctl_net_ipv6_conf_default_accept_redirects);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_source_route", check_sysctl_net_ipv6_conf_default_accept_source_route);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_redirects", check_sysctl_net_ipv4_conf_all_accept_redirects);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_source_route", check_sysctl_net_ipv4_conf_all_accept_source_route);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_log_martians", check_sysctl_net_ipv4_conf_all_log_martians);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_rp_filter", check_sysctl_net_ipv4_conf_all_rp_filter);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_secure_redirects", check_sysctl_net_ipv4_conf_all_secure_redirects);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_send_redirects", check_sysctl_net_ipv4_conf_all_send_redirects);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_redirects", check_sysctl_net_ipv4_conf_default_accept_redirects);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_source_route", check_sysctl_net_ipv4_conf_default_accept_source_route);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_log_martians", check_sysctl_net_ipv4_conf_default_log_martians);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_rp_filter", check_sysctl_net_ipv4_conf_default_rp_filter);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_secure_redirects", check_sysctl_net_ipv4_conf_default_secure_redirects);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_send_redirects", check_sysctl_net_ipv4_conf_default_send_redirects);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_echo_ignore_broadcasts", check_sysctl_net_ipv4_icmp_echo_ignore_broadcasts);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_ignore_bogus_error_responses", check_sysctl_net_ipv4_icmp_ignore_bogus_error_responses);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_tcp_syncookies", check_sysctl_net_ipv4_tcp_syncookies);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_ip_forward", check_sysctl_net_ipv4_ip_forward);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_fs_suid_dumpable", check_sysctl_fs_suid_dumpable);
    patch_rule_check("xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space", check_sysctl_kernel_randomize_va_space);

    /* Mount options on /dev/shm, /home, /tmp, /var, /var/log, /var/log/audit, /var/tmp */
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev", check_mount_option_dev_shm_nodev);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_dev_shm_noexec", check_mount_option_dev_shm_noexec);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nosuid", check_mount_option_dev_shm_nosuid);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_home_nodev", check_mount_option_home_nodev);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_home_nosuid", check_mount_option_home_nosuid);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_tmp_nodev", check_mount_option_tmp_nodev);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_tmp_noexec", check_mount_option_tmp_noexec);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_tmp_nosuid", check_mount_option_tmp_nosuid);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_nodev", check_mount_option_var_nodev);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_nosuid", check_mount_option_var_nosuid);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_log_nodev", check_mount_option_var_log_nodev);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_log_noexec", check_mount_option_var_log_noexec);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_log_nosuid", check_mount_option_var_log_nosuid);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nodev", check_mount_option_var_log_audit_nodev);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_noexec", check_mount_option_var_log_audit_noexec);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nosuid", check_mount_option_var_log_audit_nosuid);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nodev", check_mount_option_var_tmp_nodev);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_tmp_noexec", check_mount_option_var_tmp_noexec);
    patch_rule_check("xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nosuid", check_mount_option_var_tmp_nosuid);

    /* Account structural rules */
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_no_uid_except_zero", check_accounts_no_uid_except_zero);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_root_gid_zero", check_accounts_root_gid_zero);
    patch_rule_check("xccdf_org.ssgproject.content_rule_no_empty_passwords_etc_shadow", check_no_empty_passwords_etc_shadow);
    patch_rule_check("xccdf_org.ssgproject.content_rule_gid_passwd_group_same", check_gid_passwd_group_same);
    patch_rule_check("xccdf_org.ssgproject.content_rule_no_shelllogin_for_systemaccounts", check_no_shelllogin_for_systemaccounts);

    /* login.defs age and umask defaults */
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs", check_accounts_maximum_age_login_defs);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs", check_accounts_minimum_age_login_defs);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_warn_age_login_defs", check_accounts_password_warn_age_login_defs);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs", check_accounts_umask_etc_login_defs);

    /* umask in shell rc files */
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc", check_accounts_umask_etc_bashrc);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile", check_accounts_umask_etc_profile);

    /* Interactive session timeout */
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_tmout", check_accounts_tmout);

    /* Per-user home directory and dotfile rules */
    patch_rule_check("xccdf_org.ssgproject.content_rule_no_forward_files", check_no_forward_files);
    patch_rule_check("xccdf_org.ssgproject.content_rule_no_netrc_files", check_no_netrc_files);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_user_interactive_home_directory_exists", check_accounts_user_interactive_home_directory_exists);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_ownership_home_directories", check_file_ownership_home_directories);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupownership_home_directories", check_file_groupownership_home_directories);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_home_directories", check_file_permissions_home_directories);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_user_dot_user_ownership", check_accounts_user_dot_user_ownership);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_user_dot_group_ownership", check_accounts_user_dot_group_ownership);

    /* Kernel modules disabled via modprobe.d */
    patch_rule_check("xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled", check_kernel_module_cramfs_disabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled", check_kernel_module_usb_storage_disabled);

    /* systemd service / socket state */
    patch_rule_check("xccdf_org.ssgproject.content_rule_service_cron_enabled", check_service_cron_enabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_service_rsyslog_enabled", check_service_rsyslog_enabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_service_systemd-journald_enabled", check_service_systemd_journald_enabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_service_nftables_enabled", check_service_nftables_enabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_service_ufw_enabled", check_service_ufw_enabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_service_autofs_disabled", check_service_autofs_disabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_service_apport_disabled", check_service_apport_disabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_service_avahi-daemon_disabled", check_service_avahi_daemon_disabled);
    patch_rule_check("xccdf_org.ssgproject.content_rule_socket_systemd-journal-remote_disabled", check_socket_systemd_journal_remote_disabled);

    /* dpkg package install state */
    patch_rule_check("xccdf_org.ssgproject.content_rule_package_apparmor_installed", check_package_apparmor_installed);
    patch_rule_check("xccdf_org.ssgproject.content_rule_package_rsyslog_installed", check_package_rsyslog_installed);
    patch_rule_check("xccdf_org.ssgproject.content_rule_package_systemd-journal-remote_installed", check_package_systemd_journal_remote_installed);
    patch_rule_check("xccdf_org.ssgproject.content_rule_package_iptables_installed", check_package_iptables_installed);
    patch_rule_check("xccdf_org.ssgproject.content_rule_package_nftables_installed", check_package_nftables_installed);
    patch_rule_check("xccdf_org.ssgproject.content_rule_package_iptables-persistent_removed", check_package_iptables_persistent_removed);
    patch_rule_check("xccdf_org.ssgproject.content_rule_package_ufw_removed", check_package_ufw_removed);
    patch_rule_check("xccdf_org.ssgproject.content_rule_package_avahi_removed", check_package_avahi_removed);

    /* Audit subsystem configuration files */
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_ownership_audit_configuration", check_file_ownership_audit_configuration);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupownership_audit_configuration", check_file_groupownership_audit_configuration);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_etc_audit_auditd", check_file_permissions_etc_audit_auditd_conf);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_etc_audit_rulesd", check_file_permissions_etc_audit_rulesd);

    /* /var/log/audit ownership / mode */
    patch_rule_check("xccdf_org.ssgproject.content_rule_directory_permissions_var_log_audit", check_directory_permissions_var_log_audit_dir);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_ownership_var_log_audit_stig", check_file_ownership_var_log_audit_stig);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_group_ownership_var_log_audit", check_file_group_ownership_var_log_audit);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_var_log_audit", check_file_permissions_var_log_audit);

    /* Audit binaries */
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_ownership_audit_binaries", check_file_ownership_audit_binaries);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_groupownership_audit_binaries", check_file_groupownership_audit_binaries);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_audit_binaries", check_file_permissions_audit_binaries);

    /* GRUB config */
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_owner_grub2_cfg", check_file_owner_grub2_cfg);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_grub2_cfg", check_file_permissions_grub2_cfg);

    /* journald */
    patch_rule_check("xccdf_org.ssgproject.content_rule_journald_compress", check_journald_compress);
    patch_rule_check("xccdf_org.ssgproject.content_rule_journald_storage", check_journald_storage);

    /* rsyslog */
    patch_rule_check("xccdf_org.ssgproject.content_rule_rsyslog_filecreatemode", check_rsyslog_filecreatemode);

    /* Coredumps, wireless, wheel group */
    patch_rule_check("xccdf_org.ssgproject.content_rule_disable_users_coredumps", check_disable_users_coredumps);
    patch_rule_check("xccdf_org.ssgproject.content_rule_wireless_disable_interfaces", check_wireless_disable_interfaces);
    patch_rule_check("xccdf_org.ssgproject.content_rule_ensure_pam_wheel_group_empty", check_ensure_pam_wheel_group_empty);

    /* /etc/shadow age checks (require root readable shadow) */
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_set_max_life_existing", check_accounts_password_set_max_life_existing);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_set_min_life_existing", check_accounts_password_set_min_life_existing);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_password_last_change_is_in_past", check_accounts_password_last_change_is_in_past);
    patch_rule_check("xccdf_org.ssgproject.content_rule_ensure_root_password_configured", check_ensure_root_password_configured);

    /* PAM faillock and pam_wheel for su */
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_interval", check_accounts_passwords_pam_faillock_interval);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time", check_accounts_passwords_pam_faillock_unlock_time);
    patch_rule_check("xccdf_org.ssgproject.content_rule_use_pam_wheel_group_for_su", check_use_pam_wheel_group_for_su);

    /* AppArmor */
    patch_rule_check("xccdf_org.ssgproject.content_rule_all_apparmor_profiles_in_enforce_complain_mode", check_all_apparmor_profiles_in_enforce_complain_mode);
    patch_rule_check("xccdf_org.ssgproject.content_rule_grub2_enable_apparmor", check_grub2_enable_apparmor);

    /* GRUB password */
    patch_rule_check("xccdf_org.ssgproject.content_rule_grub2_password", check_grub2_password);
    patch_rule_check("xccdf_org.ssgproject.content_rule_grub2_uefi_password", check_grub2_uefi_password);

    /* root PATH and interactive-user umask composite */
    patch_rule_check("xccdf_org.ssgproject.content_rule_root_path_no_dot", check_root_path_no_dot);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_umask_interactive_users", check_accounts_umask_interactive_users);

    /* useradd INACTIVE */
    patch_rule_check("xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration", check_account_disable_post_pw_expiration);

    /* rsyslog network behavior */
    patch_rule_check("xccdf_org.ssgproject.content_rule_rsyslog_nolisten", check_rsyslog_nolisten);
    patch_rule_check("xccdf_org.ssgproject.content_rule_rsyslog_remote_loghost", check_rsyslog_remote_loghost);

    /* Firewall default policies */
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_iptables_default_rule", check_set_iptables_default_rule);
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_ip6tables_default_rule", check_set_ip6tables_default_rule);
    patch_rule_check("xccdf_org.ssgproject.content_rule_nftables_ensure_default_deny_policy", check_nftables_ensure_default_deny_policy);
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_ufw_default_rule", check_set_ufw_default_rule);

    /* /var/log permissions tree walk */
    patch_rule_check("xccdf_org.ssgproject.content_rule_permissions_local_var_log", check_permissions_local_var_log);

    /* Loopback firewall traffic */
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_loopback_traffic", check_set_loopback_traffic);
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_ipv6_loopback_traffic", check_set_ipv6_loopback_traffic);
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_ufw_loopback_traffic", check_set_ufw_loopback_traffic);
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_nftables_loopback_traffic", check_set_nftables_loopback_traffic);

    /* nftables structural */
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_nftables_table", check_set_nftables_table);
    patch_rule_check("xccdf_org.ssgproject.content_rule_set_nftables_base_chain", check_set_nftables_base_chain);
    patch_rule_check("xccdf_org.ssgproject.content_rule_nftables_rules_permanent", check_nftables_rules_permanent);

    /* Listening ports cross-checked against firewall rules */
    patch_rule_check("xccdf_org.ssgproject.content_rule_iptables_rules_for_open_ports", check_iptables_rules_for_open_ports);
    patch_rule_check("xccdf_org.ssgproject.content_rule_ip6tables_rules_for_open_ports", check_ip6tables_rules_for_open_ports);
    patch_rule_check("xccdf_org.ssgproject.content_rule_ufw_rules_for_open_ports", check_ufw_rules_for_open_ports);

    /* Filesystem walks */
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable", check_file_permissions_unauthorized_world_writable);
    patch_rule_check("xccdf_org.ssgproject.content_rule_no_files_unowned_by_user", check_no_files_unowned_by_user);
    patch_rule_check("xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned", check_file_permissions_ungroupowned);

    /* PATH dir writability */
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write", check_accounts_root_path_dirs_no_write);
    patch_rule_check("xccdf_org.ssgproject.content_rule_accounts_user_dot_no_world_writable_programs", check_accounts_user_dot_no_world_writable_programs);
}

/* Define HARDN_NO_MAIN to compile the engine without its entry point, e.g.
 * when a fuzz / sanitizer harness #includes this file to reach the static
 * parser functions directly. The normal build leaves main() in place. */
#ifndef HARDN_NO_MAIN
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
#endif /* HARDN_NO_MAIN */
