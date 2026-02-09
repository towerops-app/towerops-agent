#include "snmp_helper.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

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
