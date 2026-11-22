package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type ClientNetstack struct {
	s       *stack.Stack
	linkEP  *channel.Endpoint
	ctx     context.Context
	cancel  context.CancelFunc
	writeMu sync.Mutex
	onOut   func(pkt []byte) error
}

func NewClientNetstack(onOut func(pkt []byte) error) (*ClientNetstack, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	const nicID = tcpip.NICID(1)
	linkEP := channel.New(512, 1380, "")

	if err := s.CreateNIC(nicID, linkEP); err != nil {
		cancel()
		return nil, errString(err)
	}

	// Прозрачный режим маршрутизации: принимаем пакеты на любые внешние IP
	_ = s.SetPromiscuousMode(nicID, true)
	_ = s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	modBuf := tcpip.TCPModerateReceiveBufferOption(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &modBuf)

	ns := &ClientNetstack{
		s:      s,
		linkEP: linkEP,
		ctx:    ctx,
		cancel: cancel,
		onOut:  onOut,
	}

	// Обработчик исходящих TCP-соединений клиента -> обычный net.Dial в интернет
	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

		outConn, err := net.DialTimeout("tcp4", dst, 10*time.Second)
		if err != nil {
			r.Complete(true) // RST
			return
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			_ = outConn.Close()
			r.Complete(true)
			return
		}
		r.Complete(false)

		inConn := gonet.NewTCPConn(&wq, ep)
		go func() {
			defer inConn.Close()
			defer outConn.Close()
			done := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(outConn, inConn)
				done <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(inConn, outConn)
				done <- struct{}{}
			}()
			select {
			case <-done:
			case <-ctx.Done():
			}
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// Обработчик UDP-потоков (DNS 1.1.1.1:53, QUIC и т.д.)
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			return false
		}
		inConn := gonet.NewUDPConn(&wq, ep)

		outConn, err := net.DialTimeout("udp4", dst, 5*time.Second)
		if err != nil {
			_ = inConn.Close()
			return true
		}

		go func() {
			defer inConn.Close()
			defer outConn.Close()
			done := make(chan struct{}, 2)
			go func() {
				buf := make([]byte, 2048)
				for {
					_ = inConn.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := inConn.Read(buf)
					if err != nil {
						break
					}
					if _, err := outConn.Write(buf[:n]); err != nil {
						break
					}
				}
				done <- struct{}{}
			}()
			go func() {
				buf := make([]byte, 2048)
				for {
					_ = outConn.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := outConn.Read(buf)
					if err != nil {
						break
					}
					if _, err := inConn.Write(buf[:n]); err != nil {
						break
					}
				}
				done <- struct{}{}
			}()
			select {
			case <-done:
			case <-ctx.Done():
			}
		}()
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	// Цикл чтения ответных IPv4-пакетов из gVisor -> отправка клиенту в WinRM-туннель
	go ns.outboundLoop()

	return ns, nil
}

func (ns *ClientNetstack) outboundLoop() {
	for {
		pkt := ns.linkEP.ReadContext(ns.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		raw := v.AsSlice()
		if len(raw) >= 20 {
			_ = ns.writeToClient(raw)
		}
		v.Release()
		pkt.DecRef()
	}
}

func (ns *ClientNetstack) writeToClient(raw []byte) error {
	ns.writeMu.Lock()
	defer ns.writeMu.Unlock()
	return ns.onOut(raw)
}

// InjectPacket принимает сырой IPv4-пакет от Android-клиента
func (ns *ClientNetstack) InjectPacket(raw []byte) {
	if len(raw) < 20 || (raw[0]>>4) != 4 {
		return
	}

	// Перехват ICMP Echo Request (ping 8.8.8.8), чтобы пинг работал без root
	if raw[9] == 1 {
		ihl := int(raw[0]&0x0f) * 4
		if len(raw) >= ihl+8 && raw[ihl] == 8 {
			pktCopy := make([]byte, len(raw))
			copy(pktCopy, raw)
			go ns.handleICMPEcho(pktCopy, ihl)
			return
		}
	}

	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	ns.linkEP.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()
}

func (ns *ClientNetstack) handleICMPEcho(req []byte, ihl int) {
	dstIP := net.IPv4(req[16], req[17], req[18], req[19]).String()
	cmd := exec.CommandContext(ns.ctx, "ping", "-c", "1", "-W", "2", dstIP)
	if err := cmd.Run(); err != nil {
		return
	}

	// Формируем валидный IPv4 ICMP Echo Reply (Type=0)
	rep := make([]byte, len(req))
	copy(rep, req)

	// Меняем SrcIP и DstIP местами
	copy(rep[12:16], req[16:20])
	copy(rep[16:20], req[12:16])
	rep[8] = 64 // TTL

	// Пересчитываем контрольную сумму IPv4
	rep[10] = 0
	rep[11] = 0
	binary.BigEndian.PutUint16(rep[10:12], inetChecksum(rep[:ihl]))

	// ICMP Type = 0 (Echo Reply) + контрольная сумма ICMP
	rep[ihl] = 0
	rep[ihl+2] = 0
	rep[ihl+3] = 0
	binary.BigEndian.PutUint16(rep[ihl+2:ihl+4], inetChecksum(rep[ihl:]))

	_ = ns.writeToClient(rep)
}

func (ns *ClientNetstack) Close() {
	ns.cancel()
	ns.s.Close()
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type tcpipErr string

func (e tcpipErr) Error() string { return string(e) }

func errString(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return tcpipErr(err.String())
}
