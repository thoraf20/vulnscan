package scanner

import (
    "net/http"
    "time"
    "github.com/sirupsen/logrus"
    "strings"
    "net/url"
)

type WebResult struct {
    URL             string
    Status          string
    Headers         map[string]string
    Vulnerabilities []string
    Error           error
}

func ScanWeb(target string) WebResult {
    log := logrus.New()
    log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

    if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
        target = "http://" + target
    }

    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Get(target)
    result := WebResult{URL: target, Error: err}
    if err == nil {
        result.Status = resp.Status
        result.Headers = make(map[string]string)
        for k, v := range resp.Header {
            if len(v) > 0 {
                result.Headers[k] = v[0]
            }
        }
        resp.Body.Close()

        // Check insecure headers
        if _, exists := result.Headers["Strict-Transport-Security"]; !exists && strings.HasPrefix(target, "https://") {
            result.Vulnerabilities = append(result.Vulnerabilities, "Missing HSTS header (Strict-Transport-Security)")
        }
        if _, exists := result.Headers["X-Frame-Options"]; !exists {
            result.Vulnerabilities = append(result.Vulnerabilities, "Missing X-Frame-Options header (clickjacking risk)")
        }
        if _, exists := result.Headers["Content-Security-Policy"]; !exists {
            result.Vulnerabilities = append(result.Vulnerabilities, "Missing Content-Security-Policy header (XSS risk)")
        }
        if server, exists := result.Headers["Server"]; exists {
            result.Vulnerabilities = append(result.Vulnerabilities, "Server header exposed: "+server)
        }

        // Probe for XSS and SQLi
        result.Vulnerabilities = append(result.Vulnerabilities, probeXSS(target, client, log)...)
        result.Vulnerabilities = append(result.Vulnerabilities, probeSQLi(target, client, log)...)

        log.Infof("Web scan on %s: %s", target, result.Status)
        for _, vuln := range result.Vulnerabilities {
            log.Warnf("Vulnerability: %s", vuln)
        }
    } else {
        log.Warnf("Web scan failed on %s: %v", target, err)
    }
    return result
}

func probeXSS(target string, client *http.Client, log *logrus.Logger) []string {
    payloads := []string{
        "<script>alert('xss')</script>",
        "\"><script>alert('xss')</script>",
    }
    var vulnerabilities []string
    for _, payload := range payloads {
        u, err := url.Parse(target)
        if err != nil {
            log.Warnf("Invalid URL for XSS probe: %v", err)
            continue
        }
        q := u.Query()
        q.Add("q", payload)
        u.RawQuery = q.Encode()
        resp, err := client.Get(u.String())
        if err != nil {
            log.Warnf("XSS probe failed: %v", err)
            continue
        }
        defer resp.Body.Close()
        if resp.StatusCode == 200 {
            buf := make([]byte, 1024)
            n, _ := resp.Body.Read(buf)
            body := string(buf[:n])
            if strings.Contains(body, payload) {
                vulnerabilities = append(vulnerabilities, "Potential XSS vulnerability: payload reflected - "+payload)
            }
        }
    }
    return vulnerabilities
}

func probeSQLi(target string, client *http.Client, log *logrus.Logger) []string {
    payloads := []string{
        "' OR '1'='1",
        "1; DROP TABLE users --",
    }
    var vulnerabilities []string
    for _, payload := range payloads {
        u, err := url.Parse(target)
        if err != nil {
            log.Warnf("Invalid URL for SQLi probe: %v", err)
            continue
        }
        q := u.Query()
        q.Add("id", payload)
        u.RawQuery = q.Encode()
        resp, err := client.Get(u.String())
        if err != nil {
            log.Warnf("SQLi probe failed: %v", err)
            continue
        }
        defer resp.Body.Close()
        if resp.StatusCode == 200 {
            buf := make([]byte, 1024)
            n, _ := resp.Body.Read(buf)
            body := string(buf[:n])
            if strings.Contains(strings.ToLower(body), "sql") || strings.Contains(strings.ToLower(body), "error") {
                vulnerabilities = append(vulnerabilities, "Potential SQL injection vulnerability: error detected - "+payload)
            }
        }
    }
    return vulnerabilities
}