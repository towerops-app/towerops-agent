#include "snmp_helper.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void init_snmp_once(void) {
    // Initialize the SNMP library
    init_snmp("towerops-agent");

    // Configure to output numeric OIDs only (no MIB names)
    // This ensures OIDs are in format "1.3.6.1.2.1.1.1.0" not "SNMPv2-MIB::sysDescr.0"
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
                       NETSNMP_OID_OUTPUT_NUMERIC);
}

int snmp_init_library(void) {
    pthread_once(&init_once, init_snmp_once);
    return 0;
}

void* snmp_open_session(
    const char* ip_address,
    uint16_t port,
    const char* community,
    int version,
    int64_t timeout_us,
    int retries,
    const snmp_v3_config_t* v3_config,
    char* error_buf,
    size_t error_buf_len
) {
    struct snmp_session session, *sess_handle;

    // Ensure library is initialized
    snmp_init_library();

    // Initialize session structure
    snmp_sess_init(&session);

    // Set peer address with port (e.g., "192.168.1.1:161")
    // This is the modern way - remote_port field is deprecated
    char peername[256];
    snprintf(peername, sizeof(peername), "%s:%u", ip_address, port);
    session.peername = strdup(peername);
    if (!session.peername) {
        if (error_buf && error_buf_len > 0) {
            snprintf(error_buf, error_buf_len, "Failed to allocate memory for peer address");
        }
        return NULL;
    }

    // Set SNMP version
    switch (version) {
        case 1:
            session.version = SNMP_VERSION_1;
            break;
        case 2:
            session.version = SNMP_VERSION_2c;
            break;
        case 3:
            session.version = SNMP_VERSION_3;
            break;
        default:
            free(session.peername);
            if (error_buf && error_buf_len > 0) {
                snprintf(error_buf, error_buf_len, "Unsupported SNMP version: %d", version);
            }
            return NULL;
    }

    // Configure version-specific parameters
    if (version == 3) {
        // SNMPv3 configuration
        if (!v3_config || !v3_config->username) {
            free(session.peername);
            if (error_buf && error_buf_len > 0) {
                snprintf(error_buf, error_buf_len, "SNMPv3 requires username");
            }
            return NULL;
        }

        // Set security name (username)
        session.securityName = strdup(v3_config->username);
        session.securityNameLen = strlen(v3_config->username);

        // Set security level
        if (v3_config->security_level) {
            if (strcmp(v3_config->security_level, "authPriv") == 0) {
                session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
            } else if (strcmp(v3_config->security_level, "authNoPriv") == 0) {
                session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
            } else {
                session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
            }
        } else {
            session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
        }

        // Set authentication protocol and password
        if (session.securityLevel >= SNMP_SEC_LEVEL_AUTHNOPRIV) {
            if (v3_config->auth_password) {
                session.securityAuthProto = usmHMACMD5AuthProtocol;
                session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;

                if (v3_config->auth_protocol) {
                    if (strcmp(v3_config->auth_protocol, "SHA") == 0) {
                        session.securityAuthProto = usmHMACSHA1AuthProtocol;
                        session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
                    }
                }

                session.securityAuthKeyLen = USM_AUTH_KU_LEN;
                if (generate_Ku(session.securityAuthProto,
                               session.securityAuthProtoLen,
                               (u_char*)v3_config->auth_password,
                               strlen(v3_config->auth_password),
                               session.securityAuthKey,
                               &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
                    free(session.peername);
                    free((void*)session.securityName);
                    if (error_buf && error_buf_len > 0) {
                        snprintf(error_buf, error_buf_len, "Failed to generate auth key");
                    }
                    return NULL;
                }
            }
        }

        // Set privacy protocol and password
        if (session.securityLevel >= SNMP_SEC_LEVEL_AUTHPRIV) {
            if (v3_config->priv_password) {
                session.securityPrivProto = usmDESPrivProtocol;
                session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;

                if (v3_config->priv_protocol) {
                    if (strcmp(v3_config->priv_protocol, "AES") == 0) {
                        session.securityPrivProto = usmAESPrivProtocol;
                        session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
                    }
                }

                session.securityPrivKeyLen = USM_PRIV_KU_LEN;
                if (generate_Ku(session.securityAuthProto,
                               session.securityAuthProtoLen,
                               (u_char*)v3_config->priv_password,
                               strlen(v3_config->priv_password),
                               session.securityPrivKey,
                               &session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
                    free(session.peername);
                    free((void*)session.securityName);
                    if (error_buf && error_buf_len > 0) {
                        snprintf(error_buf, error_buf_len, "Failed to generate priv key");
                    }
                    return NULL;
                }
            }
        }
    } else {
        // v1/v2c: Set community string
        if (community && community[0]) {
            session.community = (u_char*)strdup(community);
            if (!session.community) {
                free(session.peername);
                if (error_buf && error_buf_len > 0) {
                    snprintf(error_buf, error_buf_len, "Failed to allocate memory for community string");
                }
                return NULL;
            }
            session.community_len = strlen(community);
        }
    }

    // Set timeout and retries
    session.timeout = timeout_us;
    session.retries = retries;

    // Open the session
    sess_handle = snmp_sess_open(&session);

    // Clean up temporary allocations
    free(session.peername);
    if (session.community) {
        // Zero out community string before freeing
        memset((void*)session.community, 0, session.community_len);
        free((void*)session.community);
    }
    if (session.securityName) {
        free((void*)session.securityName);
    }

    // Check for errors
    if (!sess_handle) {
        if (error_buf && error_buf_len > 0) {
            // Get error message from library
            int liberr, syserr;
            char *errstr;
            snmp_error(&session, &liberr, &syserr, &errstr);
            snprintf(error_buf, error_buf_len, "%s", errstr);
            free(errstr);
        }
        return NULL;
    }

    return sess_handle;
}

void snmp_close_session(void* sess_handle) {
    if (sess_handle) {
        snmp_sess_close(sess_handle);
    }
}

int snmp_get(
    void* sess_handle,
    const char* oid_str,
    void* value_buf,
    size_t value_buf_len,
    int* value_type,
    char* error_buf,
    size_t error_buf_len
) {
    if (!sess_handle || !oid_str || !value_buf || !value_type) {
        if (error_buf && error_buf_len > 0) {
            snprintf(error_buf, error_buf_len, "Invalid parameters");
        }
        return -1;
    }

    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;

    // Parse OID string
    if (!read_objid(oid_str, anOID, &anOID_len)) {
        if (error_buf && error_buf_len > 0) {
            snprintf(error_buf, error_buf_len, "Failed to parse OID: %s", oid_str);
        }
        return -1;
    }

    // Create GET PDU
    struct snmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);
    if (!pdu) {
        if (error_buf && error_buf_len > 0) {
            snprintf(error_buf, error_buf_len, "Failed to create PDU");
        }
        return -1;
    }

    // Add OID to PDU
    snmp_add_null_var(pdu, anOID, anOID_len);

    // Send request
    struct snmp_pdu *response = NULL;
    int status = snmp_sess_synch_response(sess_handle, pdu, &response);

    if (status != STAT_SUCCESS || !response) {
        if (error_buf && error_buf_len > 0) {
            if (status == STAT_TIMEOUT) {
                snprintf(error_buf, error_buf_len, "Request timeout");
            } else {
                snprintf(error_buf, error_buf_len, "Request failed");
            }
        }
        if (response) {
            snmp_free_pdu(response);
        }
        return -1;
    }

    // Extract value from response
    int result = -1;
    if (response->variables) {
        struct variable_list *var = response->variables;
        *value_type = var->type;

        switch (var->type) {
            case ASN_OCTET_STR:
            case ASN_OPAQUE:
            case ASN_IPADDRESS:
                if (var->val_len <= value_buf_len) {
                    memcpy(value_buf, var->val.string, var->val_len);
                    result = (int)var->val_len;
                } else {
                    if (error_buf && error_buf_len > 0) {
                        snprintf(error_buf, error_buf_len, "Buffer too small");
                    }
                }
                break;

            case ASN_INTEGER:
            case ASN_COUNTER:
            case ASN_GAUGE:
            case ASN_TIMETICKS:
            case ASN_UINTEGER:
                if (sizeof(long) <= value_buf_len) {
                    *((long*)value_buf) = *var->val.integer;
                    result = sizeof(long);
                }
                break;

            case ASN_COUNTER64:
                if (sizeof(struct counter64) <= value_buf_len) {
                    memcpy(value_buf, var->val.counter64, sizeof(struct counter64));
                    result = sizeof(struct counter64);
                }
                break;

            case ASN_OBJECT_ID:
                // Convert OID to string representation
                {
                    char oid_buf[256];
                    snprint_objid(oid_buf, sizeof(oid_buf), var->val.objid, var->val_len / sizeof(oid));
                    size_t oid_str_len = strlen(oid_buf);
                    if (oid_str_len <= value_buf_len) {
                        memcpy(value_buf, oid_buf, oid_str_len);
                        result = (int)oid_str_len;
                    } else {
                        if (error_buf && error_buf_len > 0) {
                            snprintf(error_buf, error_buf_len, "Buffer too small for OID string");
                        }
                    }
                }
                break;

            case ASN_NULL:
                // NULL values are valid but contain no data
                result = 0;
                break;

            default:
                // Unknown type
                if (error_buf && error_buf_len > 0) {
                    snprintf(error_buf, error_buf_len, "Unsupported type: %d", var->type);
                }
                break;
        }
    }

    snmp_free_pdu(response);
    return result;
}

int snmp_walk(
    void* sess_handle,
    const char* oid_str,
    snmp_walk_result_t* results,
    size_t max_results,
    size_t* num_results,
    char* error_buf,
    size_t error_buf_len
) {
    if (!sess_handle || !oid_str || !results || !num_results) {
        if (error_buf && error_buf_len > 0) {
            snprintf(error_buf, error_buf_len, "Invalid parameters");
        }
        return -1;
    }

    oid root[MAX_OID_LEN];
    size_t rootlen = MAX_OID_LEN;

    // Parse starting OID
    if (!read_objid(oid_str, root, &rootlen)) {
        if (error_buf && error_buf_len > 0) {
            snprintf(error_buf, error_buf_len, "Failed to parse OID: %s", oid_str);
        }
        return -1;
    }

    oid name[MAX_OID_LEN];
    size_t name_length = rootlen;
    memcpy(name, root, rootlen * sizeof(oid));

    *num_results = 0;
    int running = 1;

    while (running && *num_results < max_results) {
        // Create GETNEXT PDU
        struct snmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        if (!pdu) {
            break;
        }

        snmp_add_null_var(pdu, name, name_length);

        // Send request
        struct snmp_pdu *response = NULL;
        int status = snmp_sess_synch_response(sess_handle, pdu, &response);

        if (status != STAT_SUCCESS || !response || !response->variables) {
            if (response) {
                snmp_free_pdu(response);
            }
            break;
        }

        struct variable_list *var = response->variables;

        // Check if we've walked past the root OID
        if (var->name_length < rootlen ||
            snmp_oid_ncompare(var->name, var->name_length, root, rootlen, rootlen) != 0) {
            snmp_free_pdu(response);
            break;
        }

        // Store result
        snmp_walk_result_t *res = &results[*num_results];

        // Convert OID to string
        snprint_objid(res->oid, sizeof(res->oid), var->name, var->name_length);

        // Store value
        res->value_type = var->type;
        res->value_len = 0;

        switch (var->type) {
            case ASN_OCTET_STR:
            case ASN_OPAQUE:
            case ASN_IPADDRESS:
                if (var->val_len <= sizeof(res->value)) {
                    memcpy(res->value, var->val.string, var->val_len);
                    res->value_len = var->val_len;
                }
                break;

            case ASN_OBJECT_ID:
                // Convert OID to string representation
                {
                    char oid_buf[256];
                    snprint_objid(oid_buf, sizeof(oid_buf), var->val.objid, var->val_len / sizeof(oid));
                    size_t oid_str_len = strlen(oid_buf);
                    if (oid_str_len < sizeof(res->value)) {
                        memcpy(res->value, oid_buf, oid_str_len);
                        res->value_len = oid_str_len;
                    }
                }
                break;

            case ASN_INTEGER:
            case ASN_COUNTER:
            case ASN_GAUGE:
            case ASN_TIMETICKS:
            case ASN_UINTEGER:
                if (sizeof(long) <= sizeof(res->value)) {
                    *((long*)res->value) = *var->val.integer;
                    res->value_len = sizeof(long);
                }
                break;

            case ASN_COUNTER64:
                if (sizeof(struct counter64) <= sizeof(res->value)) {
                    memcpy(res->value, var->val.counter64, sizeof(struct counter64));
                    res->value_len = sizeof(struct counter64);
                }
                break;
        }

        if (res->value_len > 0) {
            (*num_results)++;
        }

        // Update OID for next iteration
        if (var->name_length <= MAX_OID_LEN) {
            memcpy(name, var->name, var->name_length * sizeof(oid));
            name_length = var->name_length;
        } else {
            running = 0;
        }

        snmp_free_pdu(response);
    }

    return 0;
}

/* --- Process-isolated (fork-based) operations --- */

/**
 * Write exactly `len` bytes to fd, retrying on EINTR.
 * Returns 0 on success, -1 on error.
 */
static int write_full(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/**
 * Read exactly `len` bytes from fd, retrying on EINTR.
 * Returns 0 on success, -1 on error/EOF.
 */
static int read_full(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* unexpected EOF */
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/**
 * Reset signal handlers to defaults in the child process.
 * This ensures any crash handler installed by the parent doesn't interfere.
 */
static void child_reset_signals(void) {
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);
}

/*
 * Serialize fork operations to avoid issues with concurrent forks
 * in multi-threaded processes. On macOS, concurrent fork() from
 * multiple threads can trigger Objective-C runtime crashes (SIGKILL).
 * On Linux this is still beneficial as it prevents resource exhaustion.
 */
static pthread_mutex_t fork_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef __APPLE__
/*
 * On macOS, the Objective-C runtime kills forked children from
 * multi-threaded parents by default. Our children never use Objective-C
 * and _exit() after SNMP work, so this is safe to disable.
 * Set before main() to ensure it's in place before any threads start.
 */
__attribute__((constructor))
static void disable_objc_fork_safety(void) {
    setenv("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES", 0);
}
#endif

void snmp_get_isolated(
    const char* ip_address,
    uint16_t port,
    const char* community,
    int version,
    int64_t timeout_us,
    int retries,
    const snmp_v3_config_t* v3_config,
    const char* oid_str,
    snmp_isolated_get_result_t* result
) {
    /* Initialize result to error state */
    memset(result, 0, sizeof(*result));
    result->status = -1;

    pthread_mutex_lock(&fork_mutex);

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        snprintf(result->error_buf, sizeof(result->error_buf),
                 "pipe() failed: %s", strerror(errno));
        pthread_mutex_unlock(&fork_mutex);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        snprintf(result->error_buf, sizeof(result->error_buf),
                 "fork() failed: %s", strerror(errno));
        pthread_mutex_unlock(&fork_mutex);
        return;
    }

    if (pid == 0) {
        /* === CHILD PROCESS === */
        close(pipefd[0]); /* close read end */
        child_reset_signals();
        alarm(60); /* watchdog: kill child if stuck */

        /* Disable MIB loading to prevent crashes from missing/corrupt MIB files.
         * Set env vars BEFORE init_snmp() runs (via snmp_open_session below).
         * Do NOT call init_snmp() directly here - snmp_open_session() calls
         * snmp_init_library() which uses pthread_once to initialize exactly once. */
        setenv("MIBS", "", 1);
        setenv("MIBDIRS", "", 1);

        snmp_isolated_get_result_t child_result;
        memset(&child_result, 0, sizeof(child_result));
        child_result.status = -1;

        /* Open session */
        char error_buf[512] = {0};
        void* sess = snmp_open_session(ip_address, port, community, version,
                                       timeout_us, retries, v3_config,
                                       error_buf, sizeof(error_buf));
        if (!sess) {
            snprintf(child_result.error_buf, sizeof(child_result.error_buf),
                     "%s", error_buf);
            write_full(pipefd[1], &child_result, sizeof(child_result));
            close(pipefd[1]);
            _exit(1);
        }

        /* Perform GET */
        int value_type = 0;
        int ret = snmp_get(sess, oid_str,
                          child_result.value_buf, sizeof(child_result.value_buf),
                          &value_type, child_result.error_buf,
                          sizeof(child_result.error_buf));
        snmp_close_session(sess);

        child_result.status = ret;
        child_result.value_type = value_type;
        write_full(pipefd[1], &child_result, sizeof(child_result));
        close(pipefd[1]);
        _exit(0);
    }

    /* === PARENT PROCESS === */
    close(pipefd[1]); /* close write end */

    /* Unlock after fork so other threads can proceed */
    pthread_mutex_unlock(&fork_mutex);

    /* Try to read the result from the child */
    snmp_isolated_get_result_t pipe_result;
    memset(&pipe_result, 0, sizeof(pipe_result));
    int read_ok = read_full(pipefd[0], &pipe_result, sizeof(pipe_result));
    close(pipefd[0]);

    /* Wait for child to exit */
    int wstatus = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &wstatus, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited < 0) {
        snprintf(result->error_buf, sizeof(result->error_buf),
                 "waitpid() failed: %s", strerror(errno));
        result->status = -1;
        return;
    }

    if (WIFSIGNALED(wstatus)) {
        /* Child was killed by a signal (crash) */
        result->status = -2;
        result->child_signal = WTERMSIG(wstatus);
        snprintf(result->error_buf, sizeof(result->error_buf),
                 "SNMP child process killed by signal %d", result->child_signal);
        return;
    }

    if (read_ok != 0) {
        /* Could not read from pipe but child exited normally - unexpected */
        result->status = -1;
        snprintf(result->error_buf, sizeof(result->error_buf),
                 "Failed to read result from child (exit code %d)",
                 WEXITSTATUS(wstatus));
        return;
    }

    /* Successfully read result from child */
    memcpy(result, &pipe_result, sizeof(*result));
}

void snmp_walk_isolated(
    const char* ip_address,
    uint16_t port,
    const char* community,
    int version,
    int64_t timeout_us,
    int retries,
    const snmp_v3_config_t* v3_config,
    const char* oid_str,
    snmp_isolated_walk_header_t* header,
    snmp_walk_result_t* results,
    size_t max_results
) {
    /* Initialize header to error state */
    memset(header, 0, sizeof(*header));
    header->status = -1;

    pthread_mutex_lock(&fork_mutex);

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        snprintf(header->error_buf, sizeof(header->error_buf),
                 "pipe() failed: %s", strerror(errno));
        pthread_mutex_unlock(&fork_mutex);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        snprintf(header->error_buf, sizeof(header->error_buf),
                 "fork() failed: %s", strerror(errno));
        pthread_mutex_unlock(&fork_mutex);
        return;
    }

    if (pid == 0) {
        /* === CHILD PROCESS === */
        close(pipefd[0]); /* close read end */
        child_reset_signals();
        alarm(60); /* watchdog */

        /* Disable MIB loading to prevent crashes from missing/corrupt MIB files.
         * Set env vars BEFORE init_snmp() runs (via snmp_open_session below).
         * Do NOT call init_snmp() directly here - snmp_open_session() calls
         * snmp_init_library() which uses pthread_once to initialize exactly once. */
        setenv("MIBS", "", 1);
        setenv("MIBDIRS", "", 1);

        snmp_isolated_walk_header_t child_header;
        memset(&child_header, 0, sizeof(child_header));
        child_header.status = -1;

        /* Open session */
        char error_buf[512] = {0};
        void* sess = snmp_open_session(ip_address, port, community, version,
                                       timeout_us, retries, v3_config,
                                       error_buf, sizeof(error_buf));
        if (!sess) {
            snprintf(child_header.error_buf, sizeof(child_header.error_buf),
                     "%s", error_buf);
            write_full(pipefd[1], &child_header, sizeof(child_header));
            close(pipefd[1]);
            _exit(1);
        }

        /* Allocate results buffer in child */
        snmp_walk_result_t* child_results = (snmp_walk_result_t*)calloc(
            max_results, sizeof(snmp_walk_result_t));
        if (!child_results) {
            snprintf(child_header.error_buf, sizeof(child_header.error_buf),
                     "Failed to allocate walk results buffer");
            snmp_close_session(sess);
            write_full(pipefd[1], &child_header, sizeof(child_header));
            close(pipefd[1]);
            _exit(1);
        }

        /* Perform WALK */
        size_t num_results = 0;
        int ret = snmp_walk(sess, oid_str, child_results, max_results,
                           &num_results, child_header.error_buf,
                           sizeof(child_header.error_buf));
        snmp_close_session(sess);

        child_header.status = ret;
        child_header.num_results = (uint32_t)num_results;

        /* Write header first */
        write_full(pipefd[1], &child_header, sizeof(child_header));

        /* Write each result individually (each < PIPE_BUF) */
        for (size_t i = 0; i < num_results; i++) {
            write_full(pipefd[1], &child_results[i], sizeof(snmp_walk_result_t));
        }

        free(child_results);
        close(pipefd[1]);
        _exit(0);
    }

    /* === PARENT PROCESS === */
    close(pipefd[1]); /* close write end */

    /* Unlock after fork so other threads can proceed */
    pthread_mutex_unlock(&fork_mutex);

    /* Read header from child */
    snmp_isolated_walk_header_t pipe_header;
    memset(&pipe_header, 0, sizeof(pipe_header));
    int read_ok = read_full(pipefd[0], &pipe_header, sizeof(pipe_header));

    uint32_t results_read = 0;
    if (read_ok == 0 && pipe_header.status >= 0 && pipe_header.num_results > 0) {
        /* Read individual results, capping at max_results */
        uint32_t to_read = pipe_header.num_results;
        if (to_read > (uint32_t)max_results) {
            to_read = (uint32_t)max_results;
        }
        for (uint32_t i = 0; i < to_read; i++) {
            if (read_full(pipefd[0], &results[i], sizeof(snmp_walk_result_t)) != 0) {
                break;
            }
            results_read++;
        }
    }
    close(pipefd[0]);

    /* Wait for child to exit */
    int wstatus = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &wstatus, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited < 0) {
        snprintf(header->error_buf, sizeof(header->error_buf),
                 "waitpid() failed: %s", strerror(errno));
        header->status = -1;
        return;
    }

    if (WIFSIGNALED(wstatus)) {
        /* Child was killed by a signal (crash) */
        header->status = -2;
        header->child_signal = WTERMSIG(wstatus);
        snprintf(header->error_buf, sizeof(header->error_buf),
                 "SNMP child process killed by signal %d", header->child_signal);
        return;
    }

    if (read_ok != 0) {
        header->status = -1;
        snprintf(header->error_buf, sizeof(header->error_buf),
                 "Failed to read header from child (exit code %d)",
                 WEXITSTATUS(wstatus));
        return;
    }

    /* Successfully read from child */
    memcpy(header, &pipe_header, sizeof(*header));
    header->num_results = results_read;
}

#ifdef SNMP_HELPER_TEST
int snmp_test_crash_in_child(int* child_signal) {
    if (!child_signal) return -1;
    *child_signal = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: close pipe ends and deliberately crash */
        close(pipefd[0]);
        close(pipefd[1]);
        child_reset_signals();

        /* Trigger SIGSEGV by writing to a null pointer */
        volatile int* null_ptr = NULL;
        *null_ptr = 42;
        _exit(99); /* should not reach here */
    }

    /* Parent */
    close(pipefd[0]);
    close(pipefd[1]);

    int wstatus = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &wstatus, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited < 0) return -1;

    if (WIFSIGNALED(wstatus)) {
        *child_signal = WTERMSIG(wstatus);
        return 0;
    }

    return -1; /* child didn't crash as expected */
}
#endif
