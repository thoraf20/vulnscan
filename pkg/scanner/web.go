package scanner

import (
    "net/http"
    "time"
    "github.com/sirupsen/logrus"
    "strings"
)

type WebResult struct {
    URL       string
    Status    string
    Headers   map[string]string
    Error     error
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
        log.Infof("Web scan on %s: %s", target, result.Status)
    } else {
        log.Warnf("Web scan failed on %s: %v", target, err)
    }
    return result
}