package scanner

import (
    "fmt"
    "net"
    "sync"
    "time"
"github.com/sirupsen/logrus"
)

type PortResult struct {
    Port  int
    Open  bool
    Error error
}

func ScanTCPPorts(host string, ports []int) []PortResult {
    log := logrus.New()
    log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

    var results []PortResult
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, port := range ports {
        wg.Add(1)
        go func(p int) {
            defer wg.Done()
            address := fmt.Sprintf("%s:%d", host, p)
            conn, err := net.DialTimeout("tcp", address, 2*time.Second)
            result := PortResult{Port: p, Error: err}
            if err == nil {
                result.Open = true
                conn.Close()
                log.Infof("Port %d is open on %s", p, host)
            } else {
                log.Debugf("Port %d is closed or filtered on %s: %v", p, host, err)
            }
            mu.Lock()
            results = append(results, result)
            mu.Unlock()
        }(port)
    }
    wg.Wait()
    return results
}