package cve

import (
	// "net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestLookupCVE(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	t.Run("SupportedService_HTTP", func(t *testing.T) {
		mockResponse := `{
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2023-1234",
						"descriptions": [{"value": "Test CVE for HTTP"}]
					}
				}
			]
		}`
		httpmock.RegisterResponder("GET", "=~^https://services.nvd.nist.gov/rest/json/cves/2.0.*http.*",
			httpmock.NewStringResponder(200, mockResponse))

		results := LookupCVE("http")
		assert.NotEmpty(t, results, "Expected results for http service")
		assert.NoError(t, results[0].Error, "Expected no error for http")
		assert.Equal(t, "CVE-2023-1234", results[0].CVEID, "Expected CVE ID")
		assert.Equal(t, "Test CVE for HTTP", results[0].Description, "Expected CVE description")
	})

	t.Run("UnsupportedService_Unknown", func(t *testing.T) {
		results := LookupCVE("unknown")
		assert.Len(t, results, 1, "Expected single result for unknown service")
		assert.NoError(t, results[0].Error, "Expected no error for unknown service")
		assert.Empty(t, results[0].CVEID, "Expected no CVE ID for unknown service")
		assert.Empty(t, results[0].Description, "Expected no description for unknown service")
	})

	t.Run("UnsupportedService_Port9999", func(t *testing.T) {
		results := LookupCVE("9999")
		assert.Len(t, results, 1, "Expected single result for port 9999")
		assert.NoError(t, results[0].Error, "Expected no error for port 9999")
		assert.Empty(t, results[0].CVEID, "Expected no CVE ID for port 9999")
		assert.Empty(t, results[0].Description, "Expected no description for port 9999")
	})
}