package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gosnmp/gosnmp"
)

var forwarder *gosnmp.GoSNMP

func initForwarder() error {
	if !config.ForwardTarget.Enabled {
		return nil
	}

	forwarder = &gosnmp.GoSNMP{
		Target:    config.ForwardTarget.Address,
		Port:      uint16(config.ForwardTarget.Port),
		Community: config.ForwardTarget.Community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		Retries:   3,
	}

	err := forwarder.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to forward target: %v", err)
	}

	log.Printf("Connected to forward target: %s:%d", config.ForwardTarget.Address, config.ForwardTarget.Port)
	return nil
}

func forwardTrap(packet *gosnmp.SnmpPacket) error {
	if !config.ForwardTarget.Enabled || forwarder == nil {
		return nil
	}

	pdu := gosnmp.SnmpPDU{
		Name:  "1.3.6.1.6.3.1.1.4.1.0",
		Type:  gosnmp.ObjectIdentifier,
		Value: "1.3.6.1.6.3.1.1.5.1", // Generic trap
	}

	trap := gosnmp.SnmpTrap{
		Variables: append([]gosnmp.SnmpPDU{pdu}, packet.Variables...),
	}

	_, err := forwarder.SendTrap(trap)
	if err != nil {
		return fmt.Errorf("failed to forward trap: %v", err)
	}

	log.Printf("Trap forwarded to %s:%d", config.ForwardTarget.Address, config.ForwardTarget.Port)
	return nil
}
