package scanner

import (
    "fmt"
    "net"
    "time"
    "github.com/sirupsen/logrus"
    "strings"
)

type PortResult struct {
    Port   int
    Open   bool
    Service string
}

func ScanTCPPorts(target string, ports []int) []PortResult {
    log := logrus.New()
    log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

    results := make([]PortResult, 0, len(ports))
    for _, port := range ports {
        addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
        conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
        result := PortResult{Port: port}
        if err == nil {
            result.Open = true
            // Attempt banner grabbing
            conn.SetReadDeadline(time.Now().Add(2 * time.Second))
            buffer := make([]byte, 1024)
            n, err := conn.Read(buffer)
            if err == nil {
                banner := string(buffer[:n])
                result.Service = detectService(banner, port)
            } else {
                result.Service = defaultService(port)
            }
            conn.Close()
            log.Infof("Port %d is open on %s (service: %s)", port, target, result.Service)
        } else {
            log.Warnf("Port %d is closed or filtered on %s", port, target)
        }
        results = append(results, result)
    }
    return results
}

func detectService(banner string, port int) string {
    banner = strings.ToLower(banner)
    if strings.Contains(banner, "ssh") {
        return "ssh"
    } else if strings.Contains(banner, "http") || strings.Contains(banner, "html") {
        return "http"
    } else if strings.Contains(banner, "tls") || strings.Contains(banner, "ssl") {
        return "https"
    }
    return defaultService(port)
}

func defaultService(port int) string {
    switch port {
    case 22:
        return "ssh"
    case 80:
        return "http"
    case 443:
        return "https"
    default:
        return "unknown"
    }
}