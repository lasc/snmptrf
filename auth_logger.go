package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func logAuthFailure(addr *net.UDPAddr, reason string) {
	log.Printf("Authentication failure from %s: %s", addr.IP, reason)
	
	if config.Output.AuthFailureLog == "" {
		log.Printf("Auth failure log file not specified, skipping file logging")
		return
	}

	f, err := os.OpenFile(config.Output.AuthFailureLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening auth failure log file: %v", err)
		return
	}
	defer f.Close()

	logEntry := fmt.Sprintf("%s - Authentication failure from %s: %s\n", 
		time.Now().Format(time.RFC3339), addr.IP, reason)
	
	_, err = f.WriteString(logEntry)
	if err != nil {
		log.Printf("Error writing to auth failure log file: %v", err)
	} else {
		log.Printf("Auth failure logged to file: %s", config.Output.AuthFailureLog)
	}
}
