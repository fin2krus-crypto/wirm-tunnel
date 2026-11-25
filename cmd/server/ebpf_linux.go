package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

//go:embed embedded/synack_win.o
var embeddedEbpfObj []byte

const ebpfTmpPath = "/tmp/winrm-synack-win.o"

type EbpfGuard struct {
	iface    string
	attached bool
}

func AttachWinTcpFingerprint(listenAddr string) *EbpfGuard {
	guard := &EbpfGuard{}

	// Безопасно работаем только от root и только на порту 5986
	if os.Geteuid() != 0 || !strings.HasSuffix(listenAddr, ":5986") {
		return guard
	}

	// Выставляем tcp_timestamps=0 и tcp_rmem max=12MB (ядро нативно выберет Window Scale = 8, как у Windows)
	_ = exec.Command("sysctl", "-w", "net.ipv4.tcp_timestamps=0").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.tcp_rmem=4096 131072 12582912").Run()

	if len(embeddedEbpfObj) == 0 {
		return guard
	}
	if _, err := exec.LookPath("tc"); err != nil {
		log.Printf("[WARN] tc (iproute2) не найден — eBPF SYN,ACK пропущен")
		return guard
	}

	extIface := detectDefaultInterface()
	if extIface == "" {
		return guard
	}

	if err := os.WriteFile(ebpfTmpPath, embeddedEbpfObj, 0600); err != nil {
		return guard
	}

	// clsact не мешает существующим правилам и другим сервисам
	_ = exec.Command("tc", "qdisc", "replace", "dev", extIface, "clsact").Run()

	// Уникальный pref 49598 гарантирует, что чужие фильтры не будут затронуты
	out, err := exec.Command(
		"tc", "filter", "replace", "dev", extIface,
		"egress", "pref", "49598", "handle", "1",
		"bpf", "da", "obj", ebpfTmpPath, "sec", "tc",
	).CombinedOutput()
	if err != nil {
		log.Printf("[WARN] eBPF SYN,ACK не активирован (%v: %s) — сервер продолжит работу штатно", err, strings.TrimSpace(string(out)))
		_ = os.Remove(ebpfTmpPath)
		return guard
	}

	guard.iface = extIface
	guard.attached = true
	log.Printf("[eBPF] Windows SYN,ACK TCP fingerprint active on %s:5986 (WScale=8, WinOrder)", extIface)
	return guard
}

func (g *EbpfGuard) Detach() {
	if g == nil || !g.attached || g.iface == "" {
		return
	}
	_ = exec.Command("tc", "filter", "del", "dev", g.iface, "egress", "pref", "49598").Run()
	_ = os.Remove(ebpfTmpPath)
	g.attached = false
}

func detectDefaultInterface() string {
	out, err := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func ebpfStatusString(g *EbpfGuard) string {
	if g != nil && g.attached {
		return fmt.Sprintf("active (%s)", g.iface)
	}
	return "off"
}
