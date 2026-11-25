package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	WinRMPath      = "/wsman"
	WinRMUserAgent = "Python WinRM client"
	ServerHeader   = "Microsoft-HTTPAPI/2.0"

	FrameData      byte = 0x00
	FrameKeepAlive byte = 0x01
	RoleRecv       byte = 'R'
	RoleSend       byte = 'S'
)

const WSManIdentifyResponseXML = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:IdentifyResponse><wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion><wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor><wsmid:ProductVersion>OS: 0.0.0 SP: 0.0 Stack: 3.0</wsmid:ProductVersion></wsmid:IdentifyResponse></s:Body></s:Envelope>`

const HttpSysNotFoundHTML = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Found</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Not Found</h2>
<hr><p>HTTP Error 404. The requested resource is not found.</p>
</BODY></HTML>
`

const HttpSysBadRequestHTML = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Bad Request</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Bad Request</h2>
<hr><p>HTTP Error 400. The request is badly formed.</p>
</BODY></HTML>
`

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func BuildSoapCreateShellXML(hostAddr string) string {
	if hostAddr == "" {
		hostAddr = "windows-host:5986"
	}
	msgID := randomUUID()
	timeouts := []string{"PT60S", "PT120S", "PT180S", "PT300S"}
	timeout := timeouts[mathrand.Intn(len(timeouts))]

	extraOpts := `<w:OptionSet><w:Option Name="WINRS_NOPROFILE">FALSE</w:Option></w:OptionSet>`
	if mathrand.Intn(2) == 0 {
		extraOpts = `<w:OptionSet><w:Option Name="WINRS_NOPROFILE">TRUE</w:Option><w:Option Name="WINRS_CODEPAGE">65001</w:Option></w:OptionSet>`
	}
	padSpaces := strings.Repeat(" ", 4+mathrand.Intn(140))

	return fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><env:Header><a:To>https://%s/wsman</a:To><a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize><a:MessageID>uuid:%s</a:MessageID><w:Locale mustUnderstand="false" xml:lang="en-US"/><p:DataLocale mustUnderstand="false" xml:lang="en-US"/><w:OperationTimeout>%s</w:OperationTimeout><w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI><a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>%s</env:Header><env:Body><rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>%s</env:Body></env:Envelope>`,
		hostAddr, msgID, timeout, extraOpts, padSpaces,
	)
}

func BuildSoapCreateShellResponseXML(hostAddr string) string {
	if hostAddr == "" {
		hostAddr = "windows-host:5986"
	}
	msgID := strings.ToUpper(randomUUID())
	relID := randomUUID()
	shellID := strings.ToUpper(randomUUID())
	padSpaces := strings.Repeat(" ", 4+mathrand.Intn(160))

	return fmt.Sprintf(
		`<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse</a:Action><a:MessageID>uuid:%s</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:%s</a:RelatesTo></s:Header><s:Body><x:ResourceCreated><a:Address>https://%s/wsman</a:Address><a:ReferenceParameters><w:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI><w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated><rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:ShellId>%s</rsp:ShellId><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>%s</s:Body></s:Envelope>`,
		msgID, relID, hostAddr, shellID, shellID, padSpaces,
	)
}

func BuildSoapReceiveXML(hostAddr string) string {
	if hostAddr == "" {
		hostAddr = "windows-host:5986"
	}
	msgID := randomUUID()
	shellID := strings.ToUpper(randomUUID())
	padSpaces := strings.Repeat(" ", 4+mathrand.Intn(96))
	return fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><env:Header><a:To>https://%s/wsman</a:To><w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize><a:MessageID>uuid:%s</a:MessageID><w:OperationTimeout>PT60S</w:OperationTimeout><w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI><a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action><w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet></env:Header><env:Body><rsp:Receive><rsp:DesiredStream>stdout stderr</rsp:DesiredStream></rsp:Receive>%s</env:Body></env:Envelope>`,
		hostAddr, msgID, shellID, padSpaces,
	)
}

func BuildSoapSendResponseXML(hostAddr string) string {
	if hostAddr == "" {
		hostAddr = "windows-host:5986"
	}
	msgID := strings.ToUpper(randomUUID())
	relID := randomUUID()
	padSpaces := strings.Repeat(" ", 4+mathrand.Intn(120))
	return fmt.Sprintf(
		`<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse</a:Action><a:MessageID>uuid:%s</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:%s</a:RelatesTo></s:Header><s:Body><rsp:SendResponse/>%s</s:Body></s:Envelope>`,
		msgID, relID, padSpaces,
	)
}

func BuildNTLMType1() string {
	buf := make([]byte, 40)
	copy(buf[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(buf[8:12], 1)
	binary.LittleEndian.PutUint32(buf[12:16], 0xe20882b7)
	buf[32] = 6
	buf[33] = 1
	binary.LittleEndian.PutUint16(buf[34:36], 7600)
	buf[39] = 15
	return base64.StdEncoding.EncodeToString(buf)
}

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func BuildNTLMType2(hostName string) (string, [8]byte) {
	var challenge [8]byte
	_, _ = rand.Read(challenge[:])

	targetName := encodeUTF16LE(hostName)

	var targetInfo []byte
	appendAV := func(avID uint16, val []byte) {
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr[0:2], avID)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
		targetInfo = append(targetInfo, hdr...)
		targetInfo = append(targetInfo, val...)
	}
	appendAV(2, targetName)
	appendAV(1, targetName)
	appendAV(4, targetName)
	appendAV(3, targetName)

	ft := uint64(time.Now().UnixNano()/100) + 116444736000000000
	ftBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(ftBytes, ft)
	appendAV(7, ftBytes)
	appendAV(0, []byte{})

	hdrLen := 56
	buf := make([]byte, hdrLen+len(targetName)+len(targetInfo))
	copy(buf[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(buf[8:12], 2)

	binary.LittleEndian.PutUint16(buf[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(buf[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(hdrLen))

	binary.LittleEndian.PutUint32(buf[20:24], 0xe28a8215)
	copy(buf[24:32], challenge[:])

	tiOffset := hdrLen + len(targetName)
	binary.LittleEndian.PutUint16(buf[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(buf[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(buf[44:48], uint32(tiOffset))

	buf[48] = 10
	buf[49] = 0
	binary.LittleEndian.PutUint16(buf[50:52], 20348)
	buf[55] = 15

	copy(buf[hdrLen:], targetName)
	copy(buf[tiOffset:], targetInfo)

	return base64.StdEncoding.EncodeToString(buf), challenge
}

// BuildNTLMType3SessionAuth прячет HMAC-токен, SessionID и роль канала ('R'/'S') внутри NtChallengeResponse
func BuildNTLMType3SessionAuth(psk string, serverChallenge [8]byte, sessionID [16]byte, role byte) string {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(serverChallenge[:])
	mac.Write(ts)
	mac.Write(nonce)
	mac.Write(sessionID[:])
	mac.Write([]byte{role})
	sig := mac.Sum(nil)

	var randLenByte [1]byte
	_, _ = rand.Read(randLenByte[:])
	padLen := 32 + int(randLenByte[0]%80)
	pad := make([]byte, padLen)
	_, _ = rand.Read(pad)

	ntResp := make([]byte, 0, 8+16+16+1+32+padLen)
	ntResp = append(ntResp, ts...)
	ntResp = append(ntResp, nonce...)
	ntResp = append(ntResp, sessionID[:]...)
	ntResp = append(ntResp, role)
	ntResp = append(ntResp, sig...)
	ntResp = append(ntResp, pad...)

	hdrLen := 88
	lmResp := make([]byte, 24)
	buf := make([]byte, hdrLen+len(lmResp)+len(ntResp))
	copy(buf[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(buf[8:12], 3)

	binary.LittleEndian.PutUint16(buf[12:14], uint16(len(lmResp)))
	binary.LittleEndian.PutUint16(buf[14:16], uint16(len(lmResp)))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(hdrLen))

	ntOffset := hdrLen + len(lmResp)
	binary.LittleEndian.PutUint16(buf[20:22], uint16(len(ntResp)))
	binary.LittleEndian.PutUint16(buf[22:24], uint16(len(ntResp)))
	binary.LittleEndian.PutUint32(buf[24:28], uint32(ntOffset))

	binary.LittleEndian.PutUint32(buf[60:64], 0xe2888235)
	buf[64] = 6
	buf[65] = 1
	binary.LittleEndian.PutUint16(buf[66:68], 7600)
	buf[71] = 15

	copy(buf[hdrLen:], lmResp)
	copy(buf[ntOffset:], ntResp)

	return base64.StdEncoding.EncodeToString(buf)
}

func VerifyNTLMType3SessionAuth(b64Token string, psk string, serverChallenge [8]byte) (sessionID [16]byte, role byte, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(b64Token)
	if err != nil || len(raw) < 88 {
		return sessionID, 0, false
	}
	if string(raw[0:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(raw[8:12]) != 3 {
		return sessionID, 0, false
	}
	ntLen := int(binary.LittleEndian.Uint16(raw[20:22]))
	ntOff := int(binary.LittleEndian.Uint32(raw[24:28]))
	if ntOff < 0 || ntLen < (8+16+16+1+32) || ntOff+ntLen > len(raw) {
		return sessionID, 0, false
	}
	ntResp := raw[ntOff : ntOff+ntLen]
	tsBytes := ntResp[0:8]
	nonce := ntResp[8:24]
	copy(sessionID[:], ntResp[24:40])
	role = ntResp[40]
	gotSig := ntResp[41:73]

	ts := int64(binary.BigEndian.Uint64(tsBytes))
	now := time.Now().Unix()
	if ts < now-120 || ts > now+120 {
		return sessionID, 0, false
	}

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(serverChallenge[:])
	mac.Write(tsBytes)
	mac.Write(nonce)
	mac.Write(sessionID[:])
	mac.Write([]byte{role})
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(gotSig, expectedSig) {
		return sessionID, 0, false
	}
	return sessionID, role, true
}

func fillFastRandom(b []byte) {
	for i := 0; i < len(b); i += 8 {
		v := mathrand.Uint64()
		for j := 0; j < 8 && i+j < len(b); j++ {
			b[i+j] = byte(v >> (j * 8))
		}
	}
}

// EncodeBatchFrame упаковывает пачку IPv4-пакетов (или KeepAlive) в единый блок для HTTP-отправки.
// - Мелкие блоки выравниваются под размер SOAP-сообщений (480..1280 Б), убирая паттерн коротких ACK.
// - Крупные блоки пишутся целиком, чтобы TCP-стек заполнял полные MSS (1448/1460 Б) без лишних PSH,ACK.
func EncodeBatchFrame(pkts [][]byte, frameType byte) []byte {
	payloadSize := 0
	for _, p := range pkts {
		payloadSize += 2 + len(p)
	}

	rawSize := 5 + payloadSize
	padLen := 0

	if frameType == FrameKeepAlive {
		target := 850 + mathrand.Intn(450)
		if target > rawSize {
			padLen = target - rawSize
		}
	} else if rawSize < 512 {
		target := 480 + mathrand.Intn(800)
		if target > rawSize {
			padLen = target - rawSize
		}
	} else if rawSize < 1350 {
		padLen = mathrand.Intn(96)
	}

	buf := make([]byte, rawSize+padLen)
	buf[0] = frameType
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(pkts)))
	binary.BigEndian.PutUint16(buf[3:5], uint16(padLen))

	off := 5
	for _, p := range pkts {
		binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(p)))
		off += 2
		copy(buf[off:off+len(p)], p)
		off += len(p)
	}
	if padLen > 0 {
		fillFastRandom(buf[off:])
	}
	return buf
}

// DecodeBatchFrame читает один батч-фрейм из HTTP Body (Send или chunked Receive)
func DecodeBatchFrame(r io.Reader) (frameType byte, pkts [][]byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	frameType = hdr[0]
	count := int(binary.BigEndian.Uint16(hdr[1:3]))
	padLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if count > 512 || padLen > 65535 {
		return 0, nil, errors.New("invalid batch header")
	}

	pkts = make([][]byte, 0, count)
	var lenBuf [2]byte
	for i := 0; i < count; i++ {
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return 0, nil, err
		}
		pLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if pLen > 65535 {
			return 0, nil, errors.New("packet too large")
		}
		pkt := make([]byte, pLen)
		if _, err := io.ReadFull(r, pkt); err != nil {
			return 0, nil, err
		}
		pkts = append(pkts, pkt)
	}

	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return 0, nil, err
		}
	}
	return frameType, pkts, nil
}

// WriteHTTPChunk отправляет один батч в виде HTTP/1.1 chunk одним вызовом Write()
func WriteHTTPChunk(w io.Writer, payload []byte) error {
	hdr := fmt.Sprintf("%x\r\n", len(payload))
	out := make([]byte, len(hdr)+len(payload)+2)
	copy(out, hdr)
	copy(out[len(hdr):], payload)
	copy(out[len(hdr)+len(payload):], "\r\n")
	_, err := w.Write(out)
	return err
}
