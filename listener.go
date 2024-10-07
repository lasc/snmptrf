package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/gosnmp/gosnmp"
	"github.com/sleepinggenius2/gosmi"
	"github.com/sleepinggenius2/gosmi/types"
)

func startUDPListener(address string) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		log.Fatalf("Error resolving UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Error starting UDP listener: %v", err)
	}
	defer conn.Close()

	log.Printf("UDP listener started on %s", address)

	buffer := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		go handleUDPPacket(conn, remoteAddr, buffer[:n], config)
	}
}

func handleUDPPacket(conn *net.UDPConn, addr *net.UDPAddr, buf []byte, config *Config) {
	log.Printf("DEBUG: Received UDP packet from %s, length: %d", addr, len(buf))
	log.Printf("DEBUG: Packet hex dump: %s", hex.Dump(buf))

	username, snmpVersion, err := extractUsernameFromPacket(buf, config)
	if err != nil {
		log.Printf("Error extracting username: %v", err)
		return
	}

	log.Printf("DEBUG: Extracted username: %s", username)
	log.Printf("DEBUG: SNMP version: %v", snmpVersion)

	snmpConfig, ok := SnmpConfigs[username]
	if !ok {
		log.Printf("No SNMP configuration found for user: %s", username)
		return
	}

	// Create a copy of the config
	packetConfig := *snmpConfig

	log.Printf("DEBUG: SNMP Config for user %s:", username)
	log.Printf("  Version: %v", packetConfig.Version)
	log.Printf("  SecurityModel: %v", packetConfig.SecurityModel)
	log.Printf("  MsgFlags: %v", packetConfig.MsgFlags)
	if usmParams, ok := packetConfig.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
		log.Printf("  AuthenticationProtocol: %v", usmParams.AuthenticationProtocol)
		log.Printf("  PrivacyProtocol: %v", usmParams.PrivacyProtocol)
		log.Printf("  AuthenticationPassphrase: %s", usmParams.AuthenticationPassphrase)
		log.Printf("  PrivacyPassphrase: %s", usmParams.PrivacyPassphrase)
	}

	var packet *gosnmp.SnmpPacket

	if snmpVersion == gosnmp.Version3 {
		engineID, engineErr := extractEngineIDFromPacket(buf)
		if engineErr != nil {
			log.Printf("Error extracting engineID: %v", engineErr)
			return
		}

		log.Printf("DEBUG: Extracted engineID: %x", engineID)

		usmParams := packetConfig.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		usmParams.AuthoritativeEngineID = string(engineID)

		log.Printf("DEBUG: Set AuthoritativeEngineID for user %s", username)
		log.Printf("DEBUG: AuthoritativeEngineID: %x", engineID)
	}

	log.Printf("DEBUG: About to unmarshal trap for user: %s", username)
	packet, err = packetConfig.UnmarshalTrap(buf, true)
	if err != nil {
		log.Printf("ERROR: Failed to unmarshal trap: %v", err)
		return
	}

	if packet == nil {
		log.Printf("Warning: Decoded packet is nil for user %s", username)
		return
	}

	log.Printf("Successfully decoded packet for user: %s", username)
	handlePacket(conn, addr, packet)
}

func extractUsernameFromPacket(buf []byte, config *Config) (string, gosnmp.SnmpVersion, error) {
	if len(buf) < 3 {
		return "", 0, fmt.Errorf("packet too short")
	}

	// Check if it's a SEQUENCE
	if buf[0] != 0x30 {
		return "", 0, fmt.Errorf("not a valid SNMP packet")
	}

	// Skip length byte(s)
	cursor := 1
	if buf[cursor] == 0x81 {
		cursor += 2
	} else if buf[cursor] == 0x82 {
		cursor += 3
	} else {
		cursor++
	}

	// Check SNMP version
	if cursor+2 >= len(buf) || buf[cursor] != 0x02 {
		return "", 0, fmt.Errorf("invalid SNMP version field")
	}
	cursor++
	versionLength := int(buf[cursor])
	cursor++
	if cursor+versionLength > len(buf) {
		return "", 0, fmt.Errorf("SNMP version field exceeds packet bounds")
	}
	version := buf[cursor]

	var snmpVersion gosnmp.SnmpVersion
	var username string

	if version == 0x00 {
		snmpVersion = gosnmp.Version1
	} else if version == 0x01 {
		snmpVersion = gosnmp.Version2c
	} else if version == 0x03 {
		snmpVersion = gosnmp.Version3
	} else {
		return "", 0, fmt.Errorf("unsupported SNMP version: %d", version)
	}

	if snmpVersion == gosnmp.Version1 || snmpVersion == gosnmp.Version2c {
		cursor += versionLength
		if cursor >= len(buf) || buf[cursor] != 0x04 {
			return "", 0, fmt.Errorf("expected community string, got %02x", buf[cursor])
		}
		cursor++
		if cursor >= len(buf) {
			return "", 0, fmt.Errorf("community string length missing")
		}
		length := int(buf[cursor])
		cursor++
		if cursor+length > len(buf) {
			return "", 0, fmt.Errorf("community string length exceeds packet bounds")
		}
		username = string(buf[cursor : cursor+length])
		log.Printf("DEBUG: Extracted community string: %s", username)
	} else if snmpVersion == gosnmp.Version3 {
		// Search for the username pattern: 0x04 followed by length byte and username
		for i := cursor; i < len(buf)-3; i++ {
			if buf[i] == 0x04 && buf[i+1] <= 0x20 { // OCTET STRING tag and reasonable length
				length := int(buf[i+1])
				start := i + 2
				end := start + length
				if end <= len(buf) && length > 0 {
					username = string(buf[start:end])
					// Check if the username exists in the SnmpConfigs
					if _, ok := SnmpConfigs[username]; ok {
						break
					}
				}
			}
		}
		if username == "" {
			return "", 0, fmt.Errorf("username not found in SNMPv3 packet")
		}
		log.Printf("DEBUG: Extracted SNMPv3 username: %s", username)
	}

	return username, snmpVersion, nil
}

func extractEngineIDFromPacket(buf []byte) ([]byte, error) {
	if len(buf) < 3 {
		return nil, fmt.Errorf("packet too short")
	}

	// Check if it's a SEQUENCE
	if buf[0] != 0x30 {
		return nil, fmt.Errorf("not a valid SNMP packet")
	}

	// Skip length byte(s)
	cursor := 1
	if buf[cursor] == 0x81 {
		cursor += 2
	} else if buf[cursor] == 0x82 {
		cursor += 3
	} else {
		cursor++
	}

	// Check SNMP version
	if cursor+2 >= len(buf) || buf[cursor] != 0x02 {
		return nil, fmt.Errorf("invalid SNMP version field")
	}
	cursor++
	versionLength := int(buf[cursor])
	cursor++
	if cursor+versionLength > len(buf) {
		return nil, fmt.Errorf("SNMP version field exceeds packet bounds")
	}
	version := buf[cursor]

	if version != 0x03 { // Not SNMPv3
		return nil, fmt.Errorf("not an SNMPv3 packet")
	}

	// Search for the engineID pattern: 0x04 0x08 followed by 8 bytes
	for i := cursor; i < len(buf)-10; i++ {
		if buf[i] == 0x04 && buf[i+1] == 0x08 { // OCTET STRING tag and length 8
			return buf[i+2 : i+10], nil
		}
	}

	return nil, fmt.Errorf("engineID not found in packet")
}

func handlePacket(conn *net.UDPConn, addr *net.UDPAddr, packet *gosnmp.SnmpPacket) {
	log.Printf("DEBUG: Processing SNMP packet from %s", addr)
	log.Printf("DEBUG: SNMP Version: %v", packet.Version)

	if packet.PDUType != 0 {
		log.Printf("DEBUG: PDU Type: %v", packet.PDUType)
		log.Printf("DEBUG: Request ID: %d", packet.RequestID)
		log.Printf("DEBUG: Error: %d", packet.Error)
		log.Printf("DEBUG: Error Index: %d", packet.ErrorIndex)
	}

	if packet.Variables != nil {
		log.Printf("DEBUG: Variables count: %d", len(packet.Variables))
	} else {
		log.Printf("DEBUG: No variables in packet")
	}

	switch packet.Version {
	case gosnmp.Version2c:
		log.Printf("DEBUG: Handling SNMPv2c packet")
		handleSNMPv2cPacket(conn, addr, packet)
	case gosnmp.Version3:
		log.Printf("DEBUG: Handling SNMPv3 packet")
		handleSNMPv3Packet(conn, addr, packet)
	default:
		log.Printf("DEBUG: Unsupported SNMP version: %v", packet.Version)
	}
}

func handleSNMPv2cPacket(conn *net.UDPConn, addr *net.UDPAddr, packet *gosnmp.SnmpPacket) {
	if packet.PDUType == gosnmp.InformRequest {
		log.Printf("Received SNMPv2c Inform from %s", addr)
		sendInformResponse(conn, addr, packet)
	} else {
		log.Printf("Received SNMPv2c Trap from %s", addr)
	}
	log.Printf("Community: %s", packet.Community)
	logVariables(packet.Variables)
}

func handleSNMPv3Packet(conn *net.UDPConn, addr *net.UDPAddr, packet *gosnmp.SnmpPacket) {
	log.Printf("DEBUG: Handling SNMPv3 packet from %s", addr.IP)
	if packet.SecurityParameters != nil {
		if usmParams, ok := packet.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
			log.Printf("DEBUG: Received SNMPv3 trap - Username: %s, Auth Protocol: %v, Privacy Protocol: %v",
				usmParams.UserName, usmParams.AuthenticationProtocol, usmParams.PrivacyProtocol)
		} else {
			log.Printf("DEBUG: SecurityParameters is not of type UsmSecurityParameters")
		}
	} else {
		log.Printf("DEBUG: SecurityParameters is nil")
	}

	if packet.PDUType == gosnmp.InformRequest {
		log.Printf("Received SNMPv3 Inform from %s", addr)
		sendInformResponse(conn, addr, packet)
	} else {
		log.Printf("Received SNMPv3 Trap from %s", addr)
	}

	log.Printf("Message ID: %d", packet.MsgID)
	log.Printf("Message Max Size: %d", packet.MsgMaxSize)
	log.Printf("Message Flags: %x", packet.MsgFlags)
	log.Printf("Message Security Model: %d", packet.SecurityModel)

	logVariables(packet.Variables)
}

func sendInformResponse(conn *net.UDPConn, addr *net.UDPAddr, packet *gosnmp.SnmpPacket) {
	response := &gosnmp.SnmpPacket{
		Version:            packet.Version,
		MsgFlags:           packet.MsgFlags,
		SecurityModel:      packet.SecurityModel,
		SecurityParameters: packet.SecurityParameters,
		ContextEngineID:    packet.ContextEngineID,
		ContextName:        packet.ContextName,
		Community:          packet.Community,
		PDUType:            gosnmp.GetResponse,
		MsgID:              packet.MsgID,
		RequestID:          packet.RequestID,
		MsgMaxSize:         packet.MsgMaxSize,
		Error:              0,
		ErrorIndex:         0,
		Variables:          packet.Variables,
	}

	responseBytes, err := response.MarshalMsg()
	if err != nil {
		log.Printf("Error marshaling Inform response: %v", err)
		return
	}

	log.Printf("DEBUG: Sending response: %s", hex.EncodeToString(responseBytes))

	_, err = conn.WriteToUDP(responseBytes, addr)
	if err != nil {
		log.Printf("Error sending Inform response: %v", err)
		return
	}

	log.Printf("Sent Inform response to %s", addr)
}

func logVariables(variables []gosnmp.SnmpPDU) {
	log.Printf("Variables:")
	for i, v := range variables {
		oid := v.Name
		oidName := oidToName(oid)
		typeStr := snmpTypeToString(v.Type)
		log.Printf("  Variable %d:", i)
		log.Printf("    OID: %s (%s)", oid, oidName)
		log.Printf("    Type: %s", typeStr)
		log.Printf("    Value: %v", v.Value)
	}
}

func snmpTypeToString(t gosnmp.Asn1BER) string {
	switch t {
	case gosnmp.Integer:
		return "Integer"
	case gosnmp.OctetString:
		return "OctetString"
	case gosnmp.ObjectIdentifier:
		return "ObjectIdentifier"
	case gosnmp.IPAddress:
		return "IPAddress"
	case gosnmp.Counter32:
		return "Counter32"
	case gosnmp.Gauge32:
		return "Gauge32"
	case gosnmp.TimeTicks:
		return "TimeTicks"
	case gosnmp.Opaque:
		return "Opaque"
	case gosnmp.Counter64:
		return "Counter64"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

func oidToName(oid string) string {
	node, err := gosmi.GetNodeByOID(types.OidMustFromString(oid))
	if err != nil {
		return oid // Return the original OID if translation fails
	}
	return node.Name
}
