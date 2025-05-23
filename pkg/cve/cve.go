package cve

import (
    "encoding/json"
    "net/http"
    "time"
    "github.com/sirupsen/logrus"
)

type CVEResult struct {
    CVEID       string
    Description string
    Error       error
}

func LookupCVE(port int) []CVEResult {
    log := logrus.New()
    log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

    // Map common ports to services (simplified)
    serviceMap := map[int]string{
        22:  "ssh",
        80:  "http",
        443: "https",
    }
    service, ok := serviceMap[port]
    if !ok {
        log.Warnf("No CVE lookup for port %d", port)
        return []CVEResult{{Error: nil}}
    }

    // Query NVD API (no API key for basic usage)
    url := "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + service
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Get(url)
    if err != nil {
        log.Warnf("CVE lookup failed for %s: %v", service, err)
        return []CVEResult{{Error: err}}
    }
    defer resp.Body.Close()

    // Parse response
    type nvdResponse struct {
        Vulnerabilities []struct {
            CVE struct {
                ID          string
                Descriptions []struct {
                    Value string
                }
            }
        }
    }
    var data nvdResponse
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
        log.Warnf("Failed to parse CVE response: %v", err)
        return []CVEResult{{Error: err}}
    }

    var results []CVEResult
    for _, vuln := range data.Vulnerabilities {
        if len(vuln.CVE.Descriptions) > 0 {
            results = append(results, CVEResult{
                CVEID:       vuln.CVE.ID,
                Description: vuln.CVE.Descriptions[0].Value,
            })
        }
    }
    if len(results) == 0 {
        log.Infof("No CVEs found for %s", service)
    } else {
        log.Infof("Found %d CVEs for %s", len(results), service)
    }
    return results
}