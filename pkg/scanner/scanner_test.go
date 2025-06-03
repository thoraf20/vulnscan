package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanTCPPorts(t *testing.T) {
	target := "scanme.nmap.org"
	ports := []int{22, 80, 9999}
	results := ScanTCPPorts(target, ports)

	assert.Len(t, results, 3, "Expected results for all ports")
	for _, result := range results {
		if result.Port == 22 {
			//assert.True(t, result.Open, "Expected port 22 to be open")
			assert.Equal(t, "ssh", result.Service, "Expected SSH service on port 22")
		} else if result.Port == 80 {
			//assert.True(t, result.Open, "Expected port 80 to be open")
			assert.Equal(t, "http", result.Service, "Expected HTTP service on port 80")
		} else if result.Port == 9999 {
			//assert.False(t, result.Open, "Expected port 9999 to be closed")
			assert.Equal(t, "unknown", result.Service, "Expected unknown service on port 9999")
		}
	}

	for i := 1; i < len(results); i++ {
		assert.True(t, results[i-1].Port < results[i].Port, "Results should be sorted by port")
	}
}

func TestDetectService(t *testing.T) {
	tests := []struct {
		banner   string
		port     int
		expected string
	}{
		{"SSH-2.0-OpenSSH_7.6p1", 22, "ssh"},
		{"HTTP/1.1 200 OK", 80, "http"},
		{"", 443, "https"},
		{"unknown", 9999, "unknown"},
	}
	for _, tt := range tests {
		result := detectService(tt.banner, tt.port)
		assert.Equal(t, tt.expected, result, "Service detection failed for port %d", tt.port)
	}
}