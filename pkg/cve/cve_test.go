package cve

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestLookupCVE(t *testing.T) {
    // Test supported service (http)
    t.Run("SupportedService_HTTP", func(t *testing.T) {
        results := LookupCVE("http")
        assert.NotEmpty(t, results, "Expected results for http service")
        if len(results) > 0 && results[0].Error != nil {
            t.Logf("CVE lookup error for http: %v", results[0].Error)
        } else {
            assert.NotEmpty(t, results[0].CVEID, "Expected CVE ID for http")
            assert.NotEmpty(t, results[0].Description, "Expected CVE description for http")
        }
    })

    // Test unsupported service (unknown)
    t.Run("UnsupportedService_Unknown", func(t *testing.T) {
        results := LookupCVE("unknown")
        assert.Len(t, results, 1, "Expected single result for unknown service")
        assert.NoError(t, results[0].Error, "Expected no error for unknown service")
        assert.Empty(t, results[0].CVEID, "Expected no CVE ID for unknown service")
        assert.Empty(t, results[0].Description, "Expected no description for unknown service")
    })

    // Test another unsupported service (arbitrary port)
    t.Run("UnsupportedService_Port9999", func(t *testing.T) {
        results := LookupCVE("9999")
        assert.Len(t, results, 1, "Expected single result for port 9999")
        assert.NoError(t, results[0].Error, "Expected no error for port 9999")
        assert.Empty(t, results[0].CVEID, "Expected no CVE ID for port 9999")
        assert.Empty(t, results[0].Description, "Expected no description for port 9999")
    })
}