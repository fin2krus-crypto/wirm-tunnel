package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"time"
	"unicode/utf16"
)

const (
	WinRMPath      = "/wsman?PSVersion=5.1.20348.2655"
	WinRMUserAgent = "Microsoft WinRM Client"
	ServerHeader   = "Microsoft-HTTPAPI/2.0"
)

const WSManIdentifyResponseXML = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:IdentifyResponse><wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion><wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor><wsmid:ProductVersion>OS: 0.0.0 SP: 0.0 Stack: 3.0</wsmid:ProductVersion></wsmid:IdentifyResponse></s:Body></s:Envelope>`

const HttpSysNotFoundHTML = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Found</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Not Found</h2>
<hr><p>HTTP Error 404. The requested resource is not found.</p>
</BODY></HTML>
`

const FakeSoapCreateShellXML = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Header><a:To>http://127.0.0.1:5986/wsman</a:To><w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.PowerShell</w:ResourceURI><a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action><w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize><a:MessageID>uuid:1c52d26d-7244-4d75-971e-5a8b7b0e44a1</a:MessageID><w:Locale xml:lang="en-US" s:mustUnderstand="false"/></s:Header><s:Body><rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:InputStreams>stdin pr</rsp:InputStreams><rsp:OutputStreams>stdout</rsp:OutputStreams></rsp:Shell></s:Body></s:Envelope>`

const FakeSoapCreateShellResponseXML = `<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse</a:Action><a:MessageID>uuid:8B2F1D9E-3C10-4E5A-9A01-22E4D1F5A900</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:1c52d26d-7244-4d75-971e-5a8b7b0e44a1</a:RelatesTo></s:Header><s:Body><x:ResourceCreated><a:Address>http://127.0.0.1:5986/wsman?PSVersion=5.1.20348.2655</a:Address><a:ReferenceParameters><w:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.PowerShell</w:ResourceURI><w:SelectorSet><w:Selector Name="ShellId">6A9F0C12-5B8E-4D12-8F7A-9C3E1B2D4E5F</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated><rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:ShellId>6A9F0C12-5B8E-4D12-8F7A-9C3E1B2D4E5F</rsp:ShellId><rsp:InputStreams>stdin pr</rsp:InputStreams><rsp:OutputStreams>stdout</rsp:OutputStreams></rsp:Shell></s:Body></s:Envelope>`

func BuildNTLMType1() string {
	buf := make([]byte, 40)
	copy(buf[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(buf[8:12], 1)
	binary.LittleEndian.PutUint32(buf[12:16], 0xe2088297)
	buf[32] = 10
	buf[33] = 0
	binary.LittleEndian.PutUint16(buf[34:36], 20348)
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

func BuildNTLMType3WithAuth(psk string, serverChallenge [8]byte) string {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(serverChallenge[:])
	mac.Write(ts)
	mac.Write(nonce)
	sig := mac.Sum(nil)

	var randLenByte [1]byte
	_, _ = rand.Read(randLenByte[:])
	padLen := 48 + int(randLenByte[0]%64)
	pad := make([]byte, padLen)
	_, _ = rand.Read(pad)

	ntResp := make([]byte, 0, 8+16+32+padLen)
	ntResp = append(ntResp, ts...)
	ntResp = append(ntResp, nonce...)
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

	binary.LittleEndian.PutUint32(buf[60:64], 0xe2888215)
	buf[64] = 10
	buf[65] = 0
	binary.LittleEndian.PutUint16(buf[66:68], 20348)
	buf[71] = 15

	copy(buf[hdrLen:], lmResp)
	copy(buf[ntOffset:], ntResp)

	return base64.StdEncoding.EncodeToString(buf)
}

func VerifyNTLMType3Auth(b64Token string, psk string, serverChallenge [8]byte) bool {
	raw, err := base64.StdEncoding.DecodeString(b64Token)
	if err != nil || len(raw) < 88 {
		return false
	}
	if string(raw[0:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(raw[8:12]) != 3 {
		return false
	}
	ntLen := int(binary.LittleEndian.Uint16(raw[20:22]))
	ntOff := int(binary.LittleEndian.Uint32(raw[24:28]))
	if ntOff < 0 || ntLen < (8+16+32) || ntOff+ntLen > len(raw) {
		return false
	}
	ntResp := raw[ntOff : ntOff+ntLen]
	tsBytes := ntResp[0:8]
	nonce := ntResp[8:24]
	gotSig := ntResp[24:56]

	ts := int64(binary.BigEndian.Uint64(tsBytes))
	now := time.Now().Unix()
	if ts < now-120 || ts > now+120 {
		return false
	}

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(serverChallenge[:])
	mac.Write(tsBytes)
	mac.Write(nonce)
	expectedSig := mac.Sum(nil)

	return hmac.Equal(gotSig, expectedSig)
}

func WritePaddedFrame(w io.Writer, ipPkt []byte) error {
	pktLen := len(ipPkt)
	if pktLen > 65535 {
		return errors.New("packet too large")
	}
	padLen := 0
	if pktLen > 0 && pktLen < 256 {
		padLen = 256 - pktLen
	}
	totalLen := 4 + pktLen + padLen
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(pktLen))
	binary.BigEndian.PutUint16(buf[2:4], uint16(padLen))
	copy(buf[4:4+pktLen], ipPkt)
	_, err := w.Write(buf)
	return err
}

func ReadPaddedFrame(r io.Reader, scratch []byte) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	pktLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	padLen := int(binary.BigEndian.Uint16(hdr[2:4]))

	if pktLen+padLen > len(scratch) {
		return nil, errors.New("frame exceeds buffer")
	}
	if _, err := io.ReadFull(r, scratch[:pktLen+padLen]); err != nil {
		return nil, err
	}
	return scratch[:pktLen], nil
}
