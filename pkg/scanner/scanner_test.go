package scanner

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestDetectService(t *testing.T) {
    tests := []struct {
        banner     string
        port       int
        expected   string
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