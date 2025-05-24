package cve

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestLookupCVE(t *testing.T) {
    // Test supported port (80)
    results := LookupCVE(80)
    assert.NotEmpty(t, results, "Expected results for port 80")
    if results[0].Error != nil {
        t.Logf("CVE lookup error: %v", results[0].Error)
    } else {
        assert.NotEmpty(t, results[0].CVEID, "Expected CVE ID")
        assert.NotEmpty(t, results[0].Description, "Expected CVE description")
    }

    // Test unsupported port
    results = LookupCVE(9999)
    assert.Len(t, results, 1, "Expected single result for unsupported port")
    assert.NoError(t, results[0].Error, "Expected no error for unsupported port")
    assert.Empty(t, results[0].CVEID, "Expected no CVE ID for unsupported port")
}