#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

/// This file is an openscap based compliance module for internal auditing 


#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
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
