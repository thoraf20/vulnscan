package scanner

import (
    "fmt"
    "net"
    "sync"
    "time"
    "github.com/sirupsen/logrus"
    "strings"
)

type PortResult struct {
    Port    int
    Open    bool
    Service string
}

func ScanTCPPorts(target string, ports []int) []PortResult {
    log := logrus.New()
    log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

    results := make([]PortResult, 0, len(ports))
    resultChan := make(chan PortResult, len(ports))
    var wg sync.WaitGroup

    // Limit concurrency to avoid overwhelming the network
    maxWorkers := 50
    semaphore := make(chan struct{}, maxWorkers)

    for _, port := range ports {
        wg.Add(1)
        go func(p int) {
            defer wg.Done()
            semaphore <- struct{}{} // Acquire semaphore
            defer func() { <-semaphore }() // Release semaphore

            addr := net.JoinHostPort(target, fmt.Sprintf("%d", p))
            conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
            result := PortResult{Port: p}
            if err == nil {
                result.Open = true
                // Banner grabbing
                conn.SetReadDeadline(time.Now().Add(2 * time.Second))
                buffer := make([]byte, 1024)
                n, err := conn.Read(buffer)
                if err == nil {
                    banner := string(buffer[:n])
                    result.Service = detectService(banner, p)
                } else {
                    result.Service = defaultService(p)
                }
                conn.Close()
                log.Infof("Port %d is open on %s (service: %s)", p, target, result.Service)
            } else {
                result.Service = defaultService(p)
                log.Warnf("Port %d is closed or filtered on %s", p, target)
            }
            resultChan <- result
        }(port)
    }

    // Close resultChan when all goroutines finish
    go func() {
        wg.Wait()
        close(resultChan)
    }()

    // Collect results
    for result := range resultChan {
        results = append(results, result)
    }

    // Sort results by port for consistent output
    sortResultsByPort(results)
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

func sortResultsByPort(results []PortResult) {
    for i := 0; i < len(results)-1; i++ {
        for j := i + 1; j < len(results); j++ {
            if results[i].Port > results[j].Port {
                results[i], results[j] = results[j], results[i]
            }
        }
    }
}