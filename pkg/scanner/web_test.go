package scanner

import (
    "net/http"
    "net/http/httptest"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestScanWeb(t *testing.T) {
    // Mock HTTP server
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    }))
    defer server.Close()

    // Test web scan
    result := ScanWeb(server.URL)
    assert.NoError(t, result.Error, "Expected no error")
    assert.Equal(t, "200 OK", result.Status, "Expected status 200 OK")
    assert.Contains(t, result.Headers, "Content-Type", "Expected Content-Type header")
    assert.Equal(t, "text/html", result.Headers["Content-Type"], "Expected text/html")
}

func TestScanWebInvalidURL(t *testing.T) {
    result := ScanWeb("http://invalid-url")
    assert.Error(t, result.Error, "Expected error for invalid URL")
}