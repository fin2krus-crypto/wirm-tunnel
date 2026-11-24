//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const linuxTunName = "winrm-cli0"

func openLinuxTun() (*os.File, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var ifr [40]byte
	copy(ifr[:16], linuxTunName)
	// IFF_TUN (0x0001) | IFF_NO_PI (0x1000) = 0x1001 (little-endian)
	ifr[16] = 0x01
	ifr[17] = 0x10

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("ioctl TUNSETIFF: %v", errno)
	}

	ifname := strings.TrimRight(string(ifr[:16]), "\x00")
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, "", err
	}

	return os.NewFile(uintptr(fd), ifname), ifname, nil
}

type LinuxNetworkState struct {
	mu           sync.Mutex
	configured   bool
	ifname       string
	serverIP     string
	gateway      string
	physIface    string
	usedResolved bool
	modifiedConf bool
	origConf     []byte
}

func getLinuxDefaultRoute() (gateway string, iface string, err error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("ip route show default: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		for i := 0; i < len(fields); i++ {
			if fields[i] == "via" && i+1 < len(fields) {
				gateway = fields[i+1]
			}
			if fields[i] == "dev" && i+1 < len(fields) {
				iface = fields[i+1]
			}
		}
		if iface != "" {
			return gateway, iface, nil
		}
	}
	return "", "", fmt.Errorf("default IPv4 route not found")
}

func hasSystemdResolved() bool {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "is-active", "--quiet", "systemd-resolved").Run() == nil
}

func (m *LinuxNetworkState) Setup(ifname, serverIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	gw, phys, err := getLinuxDefaultRoute()
	if err != nil {
		return err
	}

	m.ifname = ifname
	m.serverIP = serverIP
	m.gateway = gw
	m.physIface = phys

	// 1. Поднимаем интерфейс TUN
	if out, err := exec.Command("ip", "addr", "replace", "10.88.0.2/24", "dev", ifname).CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr failed: %v (%s)", err, string(out))
	}
	if out, err := exec.Command("ip", "link", "set", "dev", ifname, "mtu", "1380", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link up failed: %v (%s)", err, string(out))
	}
	_ = exec.Command("ip", "-6", "addr", "replace", "fd00:88::2/128", "dev", ifname).Run()

	// 2. Маршрут-исключение до VPN-сервера через физический шлюз
	if gw != "" {
		if out, err := exec.Command("ip", "-4", "route", "replace", serverIP+"/32", "via", gw, "dev", phys).CombinedOutput(); err != nil {
			return fmt.Errorf("bypass route failed: %v (%s)", err, string(out))
		}
	} else {
		if out, err := exec.Command("ip", "-4", "route", "replace", serverIP+"/32", "dev", phys).CombinedOutput(); err != nil {
			return fmt.Errorf("bypass route failed: %v (%s)", err, string(out))
		}
	}

	// 3. Маршрутизация всего IPv4 через TUN + блокировка утечек IPv6
	_ = exec.Command("ip", "-4", "route", "replace", "0.0.0.0/1", "dev", ifname).Run()
	_ = exec.Command("ip", "-4", "route", "replace", "128.0.0.0/1", "dev", ifname).Run()
	_ = exec.Command("ip", "-6", "route", "replace", "::/1", "dev", ifname).Run()
	_ = exec.Command("ip", "-6", "route", "replace", "8000::/1", "dev", ifname).Run()

	// 4. Настройка DNS 1.1.1.1 (внутри туннеля)
	if hasSystemdResolved() {
		_ = exec.Command("resolvectl", "dns", ifname, "1.1.1.1").Run()
		_ = exec.Command("resolvectl", "domain", ifname, "~.").Run()
		m.usedResolved = true
	} else {
		if raw, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			m.origConf = raw
		}
		if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver 1.1.1.1\n"), 0644); err == nil {
			m.modifiedConf = true
		}
	}

	m.configured = true
	return nil
}

func (m *LinuxNetworkState) UpdateOnNetworkChange() (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.configured {
		return false, ""
	}

	gw, phys, err := getLinuxDefaultRoute()
	if err != nil || phys == "" || phys == m.ifname {
		return false, ""
	}
	if gw == m.gateway && phys == m.physIface {
		return false, ""
	}

	m.gateway = gw
	m.physIface = phys

	if gw != "" {
		_ = exec.Command("ip", "-4", "route", "replace", m.serverIP+"/32", "via", gw, "dev", phys).Run()
	} else {
		_ = exec.Command("ip", "-4", "route", "replace", m.serverIP+"/32", "dev", phys).Run()
	}

	return true, fmt.Sprintf("%s (via %s)", phys, gw)
}

func (m *LinuxNetworkState) Restore() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.configured {
		return
	}
	m.configured = false

	_ = exec.Command("ip", "-4", "route", "del", "0.0.0.0/1", "dev", m.ifname).Run()
	_ = exec.Command("ip", "-4", "route", "del", "128.0.0.0/1", "dev", m.ifname).Run()
	_ = exec.Command("ip", "-6", "route", "del", "::/1", "dev", m.ifname).Run()
	_ = exec.Command("ip", "-6", "route", "del", "8000::/1", "dev", m.ifname).Run()
	_ = exec.Command("ip", "-4", "route", "del", m.serverIP+"/32").Run()

	if m.usedResolved {
		_ = exec.Command("resolvectl", "revert", m.ifname).Run()
	}
	if m.modifiedConf && len(m.origConf) > 0 {
		_ = os.WriteFile("/etc/resolv.conf", m.origConf, 0644)
	}
}
