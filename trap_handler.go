package main

import (
	"fmt"
	"log"
	"net"

	"github.com/gosnmp/gosnmp"
)

// Remove any function declarations that are already in listener.go

// If you need any helper functions specific to trap_handler.go, define them here
// For example:

func logTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	log.Println("DEBUG: logTrap function called")

	engineID := "<not available>"
	if usmParams, ok := packet.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
		engineID = fmt.Sprintf("%x", usmParams.AuthoritativeEngineID)
		log.Printf("DEBUG: UsmSecurityParameters - Username: %s, AuthProtocol: %v, PrivProtocol: %v",
			usmParams.UserName, usmParams.AuthenticationProtocol, usmParams.PrivacyProtocol)
	} else {
		log.Printf("DEBUG: SecurityParameters is not of type UsmSecurityParameters")
	}

	log.Printf("Received trap/inform from %s (Engine ID: %s)", addr.IP, engineID)
	log.Printf("SNMP Version: %d", packet.Version)
	log.Printf("Community/User: %s", packet.Community)

	for _, v := range packet.Variables {
		oidName := oidToName(v.Name)
		log.Printf("OID: %s (%s), Type: %d, Value: %v", v.Name, oidName, v.Type, v.Value)
	}
}

func handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	logTrap(packet, addr)

	// Forward the trap
	err := forwardTrap(packet)
	if err != nil {
		log.Printf("Error forwarding trap: %v", err)
	}

	// Add any additional trap handling logic here
}

// Add any other necessary functions or variables for trap_handler.go

// Make sure there are no loose statements outside of functions
