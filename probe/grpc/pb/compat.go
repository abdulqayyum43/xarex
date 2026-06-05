// compat.go — type aliases mapping hand-written names to generated protobuf names.
// This lets all existing probe code (dispatcher, scanners, relay) compile unchanged.
package pb

// ── TaskType aliases ─────────────────────────────────────────────────────────

type TaskType = ScanTask_TaskType

const (
	TaskType_HOST_DISCOVERY        TaskType = ScanTask_HOST_DISCOVERY
	TaskType_PORT_SCAN             TaskType = ScanTask_PORT_SCAN
	TaskType_SERVICE_FINGERPRINT   TaskType = ScanTask_SERVICE_FINGERPRINT
	TaskType_VULN_CHECK            TaskType = ScanTask_VULN_CHECK
	TaskType_DEFAULT_CRED_TEST     TaskType = ScanTask_DEFAULT_CRED_TEST
	TaskType_SMB_RELAY_CHECK       TaskType = ScanTask_SMB_RELAY_CHECK
	TaskType_LLMNR_POISON_CHECK    TaskType = ScanTask_LLMNR_POISON_CHECK
	TaskType_KERBEROAST_ENUM       TaskType = ScanTask_KERBEROAST_ENUM
	TaskType_ACTIVE_DIRECTORY_ENUM TaskType = ScanTask_ACTIVE_DIRECTORY_ENUM
	TaskType_CUSTOM                TaskType = ScanTask_CUSTOM
	TaskType_ASREP_ROAST_ENUM      TaskType = ScanTask_KERBEROAST_ENUM // mapped to same value
	TaskType_SSL_TLS_AUDIT         TaskType = ScanTask_SSL_TLS_AUDIT
	TaskType_HTTP_SECURITY_HEADERS TaskType = ScanTask_HTTP_SECURITY_HEADERS
	TaskType_DNS_ZONE_TRANSFER     TaskType = ScanTask_DNS_ZONE_TRANSFER
	TaskType_EXPOSED_ADMIN_PANEL   TaskType = ScanTask_EXPOSED_ADMIN_PANEL
	TaskType_SNMP_COMMUNITY_STRING TaskType = ScanTask_SNMP_COMMUNITY_STRING
	TaskType_RDP_SECURITY_CHECK    TaskType = ScanTask_RDP_SECURITY_CHECK
	TaskType_NUCLEI_SCAN           TaskType = ScanTask_NUCLEI_SCAN
)

// ── Severity aliases ─────────────────────────────────────────────────────────

type Severity = Finding_Severity

const (
	Severity_INFO     Severity = Finding_INFO
	Severity_LOW      Severity = Finding_LOW
	Severity_MEDIUM   Severity = Finding_MEDIUM
	Severity_HIGH     Severity = Finding_HIGH
	Severity_CRITICAL Severity = Finding_CRITICAL
)
