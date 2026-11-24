//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"
	ctliocginfo     = 0xc0644e03 // _IOWR('N', 3, struct ctl_info)
	sysprotoControl = 2
	utunOptIfname   = 2
)

type ctlInfo struct {
	ID   uint32
	Name [96]byte
}

func openMacUtun() (*os.File, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, "", fmt.Errorf("unix.Socket(AF_SYSTEM): %w", err)
	}

	var info ctlInfo
	copy(info.Name[:], utunControlName)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(ctliocginfo), uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("ioctl CTLIOCGINFO: %v", errno)
	}

	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.ID, Unit: 0}); err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("connect utun: %w", err)
	}

	ifname, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("getsockopt UTUN_OPT_IFNAME: %w", err)
	}
	ifname = strings.TrimRight(ifname, "\x00")

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, "", err
	}

	return os.NewFile(uintptr(fd), ifname), ifname, nil
}

func writeMacUtunIPv4(f *os.File, pkt []byte) error {
	buf := make([]byte, 4+len(pkt))
	buf[0] = 0
	buf[1] = 0
	buf[2] = 0
	buf[3] = 2 // AF_INET
	copy(buf[4:], pkt)
	_, err := f.Write(buf)
	return err
}

type MacNetworkState struct {
	mu          sync.Mutex
	configured  bool
	ifname      string
	serverIP    string
	gateway     string
	physIface   string
	serviceName string
	origDNS     []string
}

func getMacDefaultRoute() (gateway string, iface string, err error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("route get default: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		} else if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if iface == "" {
		return "", "", fmt.Errorf("default interface not found")
	}
	return gateway, iface, nil
}

func findMacNetworkService(device string) string {
	out, err := exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return ""
	}
	var currentPort string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			currentPort = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
		} else if strings.HasPrefix(line, "Device:") {
			dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if dev == device && currentPort != "" {
				return currentPort
			}
		}
	}
	return ""
}

func getMacDNSServers(serviceName string) []string {
	if serviceName == "" {
		return nil
	}
	out, err := exec.Command("networksetup", "-getdnsservers", serviceName).CombinedOutput()
	if err != nil {
		return nil
	}
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "There aren't any DNS Servers") {
		return []string{"Empty"}
	}
	var res []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if net.ParseIP(line) != nil {
			res = append(res, line)
		}
	}
	if len(res) == 0 {
		return []string{"Empty"}
	}
	return res
}

func setMacDNSServers(serviceName string, servers []string) {
	if serviceName == "" || len(servers) == 0 {
		return
	}
	args := append([]string{"-setdnsservers", serviceName}, servers...)
	_ = exec.Command("networksetup", args...).Run()
}

func (m *MacNetworkState) Setup(ifname, serverIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	gw, phys, err := getMacDefaultRoute()
	if err != nil {
		return err
	}

	m.ifname = ifname
	m.serverIP = serverIP
	m.gateway = gw
	m.physIface = phys
	m.serviceName = findMacNetworkService(phys)
	m.origDNS = getMacDNSServers(m.serviceName)

	// 1. Поднимаем интерфейс utun
	if out, err := exec.Command("ifconfig", ifname, "inet", "10.88.0.2", "10.88.0.1", "mtu", "1380", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig inet failed: %v (%s)", err, string(out))
	}
	_ = exec.Command("ifconfig", ifname, "inet6", "fd00:88::2", "prefixlen", "128").Run()

	// 2. Маршрут-исключение до самого VPN-сервера через физический шлюз
	_ = exec.Command("route", "-n", "delete", "-host", serverIP).Run()
	if gw != "" {
		if out, err := exec.Command("route", "-n", "add", "-host", serverIP, gw).CombinedOutput(); err != nil {
			return fmt.Errorf("bypass route failed: %v (%s)", err, string(out))
		}
	} else {
		_ = exec.Command("route", "-n", "add", "-host", serverIP, "-interface", phys).Run()
	}

	// 3. Маршрутизация всего IPv4 через utun + блокировка утечек IPv6
	_ = exec.Command("route", "-n", "add", "-net", "0.0.0.0/1", "-interface", ifname).Run()
	_ = exec.Command("route", "-n", "add", "-net", "128.0.0.0/1", "-interface", ifname).Run()
	_ = exec.Command("route", "-n", "add", "-inet6", "::/1", "-interface", ifname).Run()
	_ = exec.Command("route", "-n", "add", "-inet6", "8000::/1", "-interface", ifname).Run()

	// 4. DNS 1.1.1.1 (внутри туннеля)
	if m.serviceName != "" {
		setMacDNSServers(m.serviceName, []string{"1.1.1.1"})
	}

	m.configured = true
	return nil
}

// UpdateOnNetworkChange обновляет /32-маршрут и DNS при смене Wi-Fi / модема
func (m *MacNetworkState) UpdateOnNetworkChange() (changed bool, desc string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.configured {
		return false, ""
	}

	gw, phys, err := getMacDefaultRoute()
	if err != nil || phys == m.ifname || strings.HasPrefix(phys, "utun") {
		return false, ""
	}
	if gw == m.gateway && phys == m.physIface {
		return false, ""
	}

	// Восстанавливаем DNS на старом интерфейсе
	if m.serviceName != "" {
		setMacDNSServers(m.serviceName, m.origDNS)
	}

	m.gateway = gw
	m.physIface = phys
	m.serviceName = findMacNetworkService(phys)
	m.origDNS = getMacDNSServers(m.serviceName)

	_ = exec.Command("route", "-n", "delete", "-host", m.serverIP).Run()
	if gw != "" {
		_ = exec.Command("route", "-n", "add", "-host", m.serverIP, gw).Run()
	} else {
		_ = exec.Command("route", "-n", "add", "-host", m.serverIP, "-interface", phys).Run()
	}

	if m.serviceName != "" {
		setMacDNSServers(m.serviceName, []string{"1.1.1.1"})
	}

	return true, fmt.Sprintf("%s (gw %s)", phys, gw)
}

func (m *MacNetworkState) Restore() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.configured {
		return
	}
	m.configured = false

	_ = exec.Command("route", "-n", "delete", "-net", "0.0.0.0/1", "-interface", m.ifname).Run()
	_ = exec.Command("route", "-n", "delete", "-net", "128.0.0.0/1", "-interface", m.ifname).Run()
	_ = exec.Command("route", "-n", "delete", "-inet6", "::/1", "-interface", m.ifname).Run()
	_ = exec.Command("route", "-n", "delete", "-inet6", "8000::/1", "-interface", m.ifname).Run()
	_ = exec.Command("route", "-n", "delete", "-host", m.serverIP).Run()

	if m.serviceName != "" && len(m.origDNS) > 0 {
		setMacDNSServers(m.serviceName, m.origDNS)
	}
}
