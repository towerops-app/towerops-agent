#ifndef SNMP_HELPER_H
#define SNMP_HELPER_H

#include <stdint.h>
#include <stddef.h>

/**
 * Initialize the SNMP library (call once at startup)
 * Returns 0 on success, -1 on failure
 */
int snmp_init_library(void);

/**
 * SNMPv3 configuration
 */
typedef struct {
    const char* username;
    const char* auth_password;
    const char* priv_password;
    const char* auth_protocol;  // "MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"
    const char* priv_protocol;  // "DES", "AES", "AES-192", "AES-256"
    const char* security_level; // "noAuthNoPriv", "authNoPriv", "authPriv"
} snmp_v3_config_t;

/**
 * Open an SNMP session
 *
 * @param ip_address IP address of the device
 * @param port UDP port (usually 161)
 * @param community Community string for SNMPv1/v2c (ignored for v3)
 * @param version SNMP version: 1 (SNMPv1), 2 (SNMPv2c), 3 (SNMPv3)
 * @param timeout_us Timeout in microseconds
 * @param retries Number of retries
 * @param v3_config SNMPv3 configuration (NULL for v1/v2c)
 * @param error_buf Buffer for error messages (can be NULL)
 * @param error_buf_len Length of error buffer
 * @return Session handle on success, NULL on failure
 */
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
);

/**
 * Close an SNMP session
 * @param sess_handle Session handle from snmp_open_session
 */
void snmp_close_session(void* sess_handle);

/**
 * Perform SNMP GET operation
 *
 * @param sess_handle Session handle from snmp_open_session
 * @param oid_str OID string (e.g., "1.3.6.1.2.1.1.1.0")
 * @param value_buf Buffer for result value
 * @param value_buf_len Length of value buffer
 * @param value_type Output: type of value (see ASN_* constants)
 * @param error_buf Buffer for error messages (can be NULL)
 * @param error_buf_len Length of error buffer
 * @return 0 on success, -1 on error
 */
int snmp_get(
    void* sess_handle,
    const char* oid_str,
    void* value_buf,
    size_t value_buf_len,
    int* value_type,
    char* error_buf,
    size_t error_buf_len
);

/**
 * Result from SNMP WALK operation
 */
typedef struct {
    char oid[256];
    uint8_t value[1024];
    size_t value_len;
    int value_type;
} snmp_walk_result_t;

/**
 * Perform SNMP WALK operation
 *
 * @param sess_handle Session handle from snmp_open_session
 * @param oid_str Starting OID string
 * @param results Buffer for results
 * @param max_results Maximum number of results to return
 * @param num_results Output: actual number of results
 * @param error_buf Buffer for error messages (can be NULL)
 * @param error_buf_len Length of error buffer
 * @return 0 on success, -1 on error
 */
int snmp_walk(
    void* sess_handle,
    const char* oid_str,
    snmp_walk_result_t* results,
    size_t max_results,
    size_t* num_results,
    char* error_buf,
    size_t error_buf_len
);

#endif // SNMP_HELPER_H
