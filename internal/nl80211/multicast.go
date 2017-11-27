package nl80211

// nl80211_multicast_group enumeration from nl80211/nl80211.c:39
//
// WARNING: THIS IS MANUALLY CREATED. CURRENTLY THE c-for-go LIB DOES NOT
// SUPPORT .c FILES AND ENUMERATIONS DEFINED THEREWITH.
//
// SEE https://github.com/xlab/nl80211/issues/1 FOR FOLLOWUP ON SOLUTIONS.
const (
	McgrpConfig = iota
	McgrpScan
	McgrpRegulatory
	McgrpMlme
	McgrpVendor
	McgrpNan
	McgrpTestmode
)
