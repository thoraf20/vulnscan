package scanner

import (
    "net/http"
    "net/http/httptest"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestScanWeb(t *testing.T) {
    // Mock HTTP server with minimal headers
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        w.WriteHeader(http.StatusOK)
        if q := r.URL.Query().Get("q"); q != "" {
            w.Write([]byte(q))
        } else {
            w.Write([]byte("OK"))
        }
    }))
    defer server.Close()

    result := ScanWeb(server.URL)
    assert.NoError(t, result.Error, "Expected no error")
    assert.Equal(t, "200 OK", result.Status, "Expected status 200 OK")
    assert.Contains(t, result.Headers, "Content-Type", "Expected Content-Type header")
    assert.Equal(t, "text/html", result.Headers["Content-Type"], "Expected text/html")
    assert.Contains(t, result.Vulnerabilities, "Missing X-Frame-Options header (clickjacking risk)", "Expected X-Frame-Options warning")
    assert.Contains(t, result.Vulnerabilities, "Missing Content-Security-Policy header (XSS risk)", "Expected CSP warning")
    assert.Contains(t, result.Vulnerabilities, "Potential XSS vulnerability", "Expected XSS warning due to reflection")
}

func TestScanWebInvalidURL(t *testing.T) {
    result := ScanWeb("http://invalid-url")
    assert.Error(t, result.Error, "Expected error for invalid URL")
}