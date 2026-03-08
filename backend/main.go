package main

import (
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/gorilla/websocket"
)

var IPToDomain = map[string]string{
    "142.250.185.46": "Google/YouTube", "31.13.79.35": "Facebook/Instagram",
    "104.244.42.193": "Twitter/X", "13.107.42.14": "Microsoft/LinkedIn",
    "40.112.72.205": "Microsoft/Teams", "17.253.144.10": "Apple/iCloud",
    "176.32.103.205": "Amazon/AWS", "52.35.144.140": "Netflix",
    "104.199.65.170": "Spotify", "47.88.17.41": "TikTok",
    "151.101.129.140": "Reddit", "140.82.114.4": "GitHub",
    "162.159.128.233": "Discord", "149.154.167.99": "Telegram",
    "8.8.8.8": "Google DNS", "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS", "9.9.9.9": "Quad9 DNS",
}

var SuspiciousPorts = map[int]string{
    4444: "Metasploit", 5555: "Backdoor", 6667: "IRC Botnet",
    31337: "Elite", 23: "Telnet-Insecure", 3389: "RDP",
    445: "SMB-Ransomware", 139: "NetBIOS",
}

type Packet struct {
    ID           int64             `json:"id"`
    Timestamp    string            `json:"timestamp"`
    SrcIP        string            `json:"src_ip"`
    DstIP        string            `json:"dst_ip"`
    SrcPort      int               `json:"src_port"`
    DstPort      int               `json:"dst_port"`
    Protocol     string            `json:"protocol"`
    Size         int               `json:"size"`
    Summary      string            `json:"summary"`
    IsThreat     bool              `json:"is_threat"`
    RiskScore    int               `json:"risk_score"`
    ThreatReason string            `json:"threat_reason"`
    DstDomain    string            `json:"dst_domain"`
    RawHex       string            `json:"raw_hex"`
    Headers      map[string]string `json:"headers"`
    Flags        string            `json:"flags"`
    Seq          uint32            `json:"seq"`
    Ack          uint32            `json:"ack"`
    Payload      string            `json:"payload"`
    Analysis     string            `json:"analysis"`
    Level        string            `json:"level"`
    SrcMAC       string            `json:"src_mac"`
    DstMAC       string            `json:"dst_mac"`
}

type Stats struct {
    TotalPackets  int            `json:"total_packets"`
    TotalBytes    int64          `json:"total_bytes"`
    ProtocolCount map[string]int `json:"protocol_count"`
    ThreatCount   int            `json:"threat_count"`
    PacketsPerSec float64        `json:"packets_per_sec"`
    Interface     string         `json:"interface"`
    IsCapturing   bool           `json:"is_capturing"`
}

var (
    packets       []Packet
    packetMutex   sync.RWMutex
    stats         Stats
    statsMutex    sync.RWMutex
    clients       = make(map[*websocket.Conn]bool)
    clientMutex   sync.RWMutex
    upgrader      = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
    handle        *pcap.Handle
    capturing     bool
    captureMutex  sync.Mutex
    currentIface  string
    lastPackets   int
    lastBytes     int64
    lastCheck     time.Time
)

func startCapture(iface string) error {
    captureMutex.Lock()
    defer captureMutex.Unlock()

    if capturing {
        if handle != nil {
            handle.Close()
        }
        capturing = false
    }

    if iface == "" {
        iface = findInterface()
    }

    var err error
    handle, err = pcap.OpenLive(iface, 65535, true, time.Second)
    if err != nil {
        return err
    }

    currentIface = iface
    capturing = true

    statsMutex.Lock()
    stats.Interface = iface
    stats.IsCapturing = true
    statsMutex.Unlock()

    log.Printf("✅ Capturing on: %s", iface)
    broadcastStatus()

    go captureLoop(iface)
    return nil
}

func stopCapture() {
    captureMutex.Lock()
    defer captureMutex.Unlock()
    if handle != nil {
        handle.Close()
        handle = nil
    }
    capturing = false
    statsMutex.Lock()
    stats.IsCapturing = false
    statsMutex.Unlock()
    log.Println("⏹️ Stopped")
    broadcastStatus()
}

func findInterface() string {
    ifaces, _ := net.Interfaces()
    for _, i := range ifaces {
        if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
            addrs, _ := i.Addrs()
            for _, a := range addrs {
                if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil {
                    return i.Name
                }
            }
        }
    }
    return "eth0"
}

func captureLoop(iface string) {
    src := gopacket.NewPacketSource(handle, handle.LinkType())
    for pkt := range src.Packets() {
        if !capturing {
            return
        }
        processPacket(pkt, iface)
    }
}

func processPacket(pkt gopacket.Packet, iface string) {
    var srcIP, dstIP, proto, flags, srcMAC, dstMAC string
    var srcPort, dstPort int
    var seq, ack uint32
    var payload []byte
    headers := make(map[string]string)

    if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
        e := eth.(*layers.Ethernet)
        srcMAC = e.SrcMAC.String()
        dstMAC = e.DstMAC.String()
    }

    if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
        ip := ip4.(*layers.IPv4)
        srcIP = ip.SrcIP.String()
        dstIP = ip.DstIP.String()
        proto = ip.Protocol.String()
        headers["TTL"] = fmt.Sprintf("%d", ip.TTL)
    }

    if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
        ip := ip6.(*layers.IPv6)
        srcIP = ip.SrcIP.String()
        dstIP = ip.DstIP.String()
        proto = "IPv6"
    }

    if srcIP == "" {
        return
    }

    if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
        t := tcp.(*layers.TCP)
        srcPort = int(t.SrcPort)
        dstPort = int(t.DstPort)
        proto = "TCP"
        seq = t.Seq
        ack = t.Ack
        var f []string
        if t.SYN {
            f = append(f, "SYN")
        }
        if t.ACK {
            f = append(f, "ACK")
        }
        if t.FIN {
            f = append(f, "FIN")
        }
        if t.RST {
            f = append(f, "RST")
        }
        if t.PSH {
            f = append(f, "PSH")
        }
        flags = strings.Join(f, "-")
        headers["Window"] = fmt.Sprintf("%d", t.Window)
        payload = t.Payload
    }

    if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
        u := udp.(*layers.UDP)
        srcPort = int(u.SrcPort)
        dstPort = int(u.DstPort)
        proto = "UDP"
        payload = u.Payload
    }

    if dns := pkt.Layer(layers.LayerTypeDNS); dns != nil {
        proto = "DNS"
        d := dns.(*layers.DNS)
        if len(d.Questions) > 0 {
            headers["Query"] = string(d.Questions[0].Name)
        }
    }

    if pkt.Layer(layers.LayerTypeICMPv4) != nil {
        proto = "ICMP"
    }

    if arp := pkt.Layer(layers.LayerTypeARP); arp != nil {
        a := arp.(*layers.ARP)
        srcIP = net.IP(a.SourceProtAddress).String()
        dstIP = net.IP(a.DstProtAddress).String()
        proto = "ARP"
    }

    switch dstPort {
    case 443:
        proto = "HTTPS"
    case 80:
        proto = "HTTP"
    case 22:
        proto = "SSH"
    case 21:
        proto = "FTP"
    case 25:
        proto = "SMTP"
    case 3389:
        proto = "RDP"
    case 445:
        proto = "SMB"
    case 3306:
        proto = "MySQL"
    case 53:
        if proto == "UDP" {
            proto = "DNS"
        }
    }

    score, reason, level := analyzeThreat(srcIP, dstIP, dstPort, proto, payload)
    summary := getSummary(proto, srcIP, dstIP, dstPort)
    domain := IPToDomain[dstIP]

    rawData := pkt.Data()
    if len(rawData) > 1024 {
        rawData = rawData[:1024]
    }
    payloadData := payload
    if len(payloadData) > 500 {
        payloadData = payloadData[:500]
    }

    p := Packet{
        ID:           time.Now().UnixNano(),
        Timestamp:    time.Now().Format("15:04:05.000"),
        SrcIP:        srcIP,
        DstIP:        dstIP,
        SrcPort:      srcPort,
        DstPort:      dstPort,
        Protocol:     proto,
        Size:         len(pkt.Data()),
        Summary:      summary,
        IsThreat:     score >= 50,
        RiskScore:    score,
        ThreatReason: reason,
        DstDomain:    domain,
        RawHex:       hex.EncodeToString(rawData),
        Headers:      headers,
        Flags:        flags,
        Seq:          seq,
        Ack:          ack,
        Payload:      string(payloadData),
        Analysis:     getAnalysis(proto, score, reason),
        Level:        level,
        SrcMAC:       srcMAC,
        DstMAC:       dstMAC,
    }

    addPacket(p)
}

func analyzeThreat(src, dst string, port int, proto string, payload []byte) (int, string, string) {
    score := 0
    var reasons []string

    if desc, ok := SuspiciousPorts[port]; ok {
        score += 40
        reasons = append(reasons, desc)
    }

    if !isPrivate(src) {
        switch proto {
        case "SSH":
            score += 30
            reasons = append(reasons, "External SSH")
        case "RDP":
            score += 35
            reasons = append(reasons, "External RDP")
        case "SMB":
            score += 50
            reasons = append(reasons, "External SMB-Ransomware")
        }
    }

    pl := strings.ToLower(string(payload))
    bad := []string{"powershell", "cmd.exe", "wget", "mimikatz", "meterpreter", "reverse shell"}
    for _, b := range bad {
        if strings.Contains(pl, b) {
            score += 50
            reasons = append(reasons, "Malware pattern: "+b)
        }
    }

    level := "INFO"
    if score >= 80 {
        level = "CRITICAL"
    } else if score >= 60 {
        level = "HIGH"
    } else if score >= 40 {
        level = "MEDIUM"
    } else if score >= 20 {
        level = "LOW"
    }

    return min(score, 100), strings.Join(reasons, "; "), level
}

func getSummary(proto, src, dst string, port int) string {
    switch proto {
    case "DNS":
        return "DNS Query"
    case "HTTP":
        return "HTTP Web Request"
    case "HTTPS":
        return "Encrypted HTTPS"
    case "SSH":
        return "SSH Connection"
    case "RDP":
        return "Remote Desktop"
    case "SMB":
        return "Windows File Share"
    case "ICMP":
        return "Ping/Echo"
    case "ARP":
        return "ARP Resolution"
    default:
        return fmt.Sprintf("%s port %d", proto, port)
    }
}

func getAnalysis(proto string, score int, reason string) string {
    if score >= 50 {
        return fmt.Sprintf("⚠️ THREAT: %s\n\nInvestigate source IP and check for compromise.", reason)
    }
    switch proto {
    case "DNS":
        return "✓ Normal DNS query. Check domain reputation if suspicious."
    case "HTTP":
        return "⚠️ Unencrypted traffic. Check for sensitive data exposure."
    case "HTTPS":
        return "✓ Encrypted secure connection."
    case "SSH":
        return "✓ SSH connection. Verify authorized access."
    default:
        return "✓ Normal traffic pattern."
    }
}

func isPrivate(ip string) bool {
    private := []string{"192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "169.254."}
    for _, p := range private {
        if strings.HasPrefix(ip, p) {
            return true
        }
    }
    return false
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func addPacket(p Packet) {
    packetMutex.Lock()
    packets = append([]Packet{p}, packets...)
    if len(packets) > 20000 {
        packets = packets[:20000]
    }
    packetMutex.Unlock()

    statsMutex.Lock()
    stats.TotalPackets++
    stats.TotalBytes += int64(p.Size)
    stats.ProtocolCount[p.Protocol]++
    if p.IsThreat {
        stats.ThreatCount++
    }
    now := time.Now()
    if sec := now.Sub(lastCheck).Seconds(); sec >= 1 {
        stats.PacketsPerSec = float64(stats.TotalPackets-lastPackets) / sec
        lastPackets = stats.TotalPackets
        lastBytes = stats.TotalBytes
        lastCheck = now
    }
    statsMutex.Unlock()

    broadcast(p)
}

func broadcast(p Packet) {
    clientMutex.RLock()
    defer clientMutex.RUnlock()
    msg := map[string]interface{}{"type": "packet", "data": p}
    for c := range clients {
        c.WriteJSON(msg)
    }
}

func broadcastStatus() {
    clientMutex.RLock()
    defer clientMutex.RUnlock()
    statsMutex.RLock()
    msg := map[string]interface{}{"type": "status", "data": map[string]interface{}{
        "interface":     currentIface,
        "is_capturing":  capturing,
        "total_packets": stats.TotalPackets,
        "threat_count":  stats.ThreatCount,
    }}
    statsMutex.RUnlock()
    for c := range clients {
        c.WriteJSON(msg)
    }
}

func handleWS(c *gin.Context) {
    conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
    if err != nil {
        return
    }
    clientMutex.Lock()
    clients[conn] = true
    clientMutex.Unlock()
    log.Printf("📡 Client: %d", len(clients))

    broadcastStatus()
    packetMutex.RLock()
    recent := packets
    if len(recent) > 50 {
        recent = recent[:50]
    }
    packetMutex.RUnlock()
    conn.WriteJSON(map[string]interface{}{"type": "init", "data": recent})

    defer func() {
        clientMutex.Lock()
        delete(clients, conn)
        clientMutex.Unlock()
        conn.Close()
    }()

    for {
        _, msg, err := conn.ReadMessage()
        if err != nil {
            break
        }
        var cmd map[string]string
        if json.Unmarshal(msg, &cmd) == nil {
            switch cmd["action"] {
            case "start":
                startCapture(cmd["interface"])
            case "stop":
                stopCapture()
            case "clear":
                packetMutex.Lock()
                packets = nil
                packetMutex.Unlock()
                statsMutex.Lock()
                stats = Stats{ProtocolCount: make(map[string]int)}
                statsMutex.Unlock()
            }
        }
    }
}

func main() {
    stats.ProtocolCount = make(map[string]int)
    lastCheck = time.Now()

    fmt.Println("\n╔════════════════════════════════════════╗")
    fmt.Println("║   🐉 PACKETWYRM v2.0 - STABLE         ║")
    fmt.Println("╚════════════════════════════════════════╝\n")

    gin.SetMode(gin.ReleaseMode)
    r := gin.New()

    r.Use(func(c *gin.Context) {
        c.Header("Access-Control-Allow-Origin", "*")
        c.Next()
    })

    r.GET("/", func(c *gin.Context) { c.File("./frontend/index.html") })
    r.GET("/ws", handleWS)
    r.GET("/api/interfaces", func(c *gin.Context) {
        ifaces, _ := pcap.FindAllDevs()
        netIfaces, _ := net.Interfaces()
        ipMap := make(map[string]string)
        for _, i := range netIfaces {
            addrs, _ := i.Addrs()
            for _, a := range addrs {
                if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil {
                    ipMap[i.Name] = ip.IP.String()
                }
            }
        }
        var result []map[string]interface{}
        for _, i := range ifaces {
            isUp := false
            if n, e := net.InterfaceByName(i.Name); e == nil && n.Flags&net.FlagUp != 0 {
                isUp = true
            }
            result = append(result, map[string]interface{}{
                "name": i.Name,
                "ip":   ipMap[i.Name],
                "up":   isUp,
            })
        }
        c.JSON(200, result)
    })
    r.GET("/api/export", func(c *gin.Context) {
        packetMutex.RLock()
        defer packetMutex.RUnlock()
        var csv strings.Builder
        csv.WriteString("Time,Source,Destination,Protocol,Size,Threat,Level\n")
        for _, p := range packets {
            csv.WriteString(fmt.Sprintf("%s,%s:%d,%s:%d,%s,%d,%v,%s\n",
                p.Timestamp, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Protocol, p.Size, p.IsThreat, p.Level))
        }
        c.Header("Content-Type", "text/csv")
        c.Header("Content-Disposition", "attachment; filename=packets.csv")
        c.String(200, csv.String())
    })
    r.Static("/static", "./frontend")

    log.Println("🚀 http://localhost:8080")
    log.Fatal(r.Run(":8080"))
}
