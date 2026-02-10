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

/**
 * Result from isolated (fork-based) SNMP GET operation.
 * status >= 0: value_len (success), -1: error, -2: child crash
 */
typedef struct {
    int status;
    int value_type;
    int child_signal;
    char error_buf[512];
    uint8_t value_buf[1024];
} snmp_isolated_get_result_t;

/**
 * Header for isolated SNMP WALK result stream.
 * status 0: success, -1: error, -2: child crash
 */
typedef struct {
    int status;
    uint32_t num_results;
    int child_signal;
    char error_buf[512];
} snmp_isolated_walk_header_t;

/**
 * Perform an SNMP GET in a forked child process for crash isolation.
 *
 * @param ip_address IP address of the device
 * @param port UDP port (usually 161)
 * @param community Community string for SNMPv1/v2c
 * @param version SNMP version: 1 (SNMPv1), 2 (SNMPv2c), 3 (SNMPv3)
 * @param timeout_us Timeout in microseconds
 * @param retries Number of retries
 * @param v3_config SNMPv3 configuration (NULL for v1/v2c)
 * @param oid_str OID string to GET
 * @param result Output result structure
 */
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
);

/**
 * Perform an SNMP WALK in a forked child process for crash isolation.
 *
 * @param ip_address IP address of the device
 * @param port UDP port (usually 161)
 * @param community Community string for SNMPv1/v2c
 * @param version SNMP version: 1 (SNMPv1), 2 (SNMPv2c), 3 (SNMPv3)
 * @param timeout_us Timeout in microseconds
 * @param retries Number of retries
 * @param v3_config SNMPv3 configuration (NULL for v1/v2c)
 * @param oid_str Starting OID string to WALK
 * @param header Output header (status, num_results, error)
 * @param results Output buffer for walk results
 * @param max_results Maximum number of results
 */
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
);

#ifdef SNMP_HELPER_TEST
/**
 * Test helper: deliberately crashes (SIGSEGV) in a forked child.
 * Returns 0 on success (child crashed as expected), -1 on error.
 * child_signal receives the signal that killed the child.
 */
int snmp_test_crash_in_child(int* child_signal);
#endif

#endif // SNMP_HELPER_H
