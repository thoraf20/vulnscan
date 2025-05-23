package scanner

import (
    "fmt"
    "net"
    "time"
    "github.com/sirupsen/logrus"
)

type PortResult struct {
    Port  int
    Open  bool
    Error error
}

func ScanTCPPort(host string, port int) PortResult {
    log := logrus.New()
    log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", address, 2*time.Second)
    result := PortResult{Port: port, Error: err}
    if err == nil {
        result.Open = true
        conn.Close()
        log.Infof("Port %d is open on %s", port, host)
    } else {
        log.Debugf("Port %d is closed or filtered on %s: %v", port, host, err)
    }
    return result
}