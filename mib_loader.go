package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/sleepinggenius2/gosmi"
)

func initMIBs(mibDirs []string) error {
	gosmi.Init()
	log.Printf("Current GOSMI path: %s", gosmi.GetPath())

	for _, dir := range mibDirs {
		gosmi.AppendPath(dir)
	}
	log.Printf("Updated GOSMI path: %s", gosmi.GetPath())

	essentialMIBs := []string{"SNMPv2-MIB", "IF-MIB", "IP-MIB", "TCP-MIB", "UDP-MIB"}
	for _, mib := range essentialMIBs {
		if _, err := gosmi.LoadModule(mib); err != nil {
			log.Printf("Error loading essential MIB %s: %v", mib, err)
		} else {
			log.Printf("Successfully loaded essential MIB: %s", mib)
		}
	}

	// Load all MIBs in the specified directories
	modules := []string{}
	for _, dir := range mibDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			log.Printf("Error reading MIBs from %s: %v", dir, err)
			continue
		}
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(strings.ToUpper(file.Name()), ".MIB") {
				moduleName := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
				if _, err := gosmi.LoadModule(moduleName); err != nil {
					log.Printf("Error loading MIB %s: %v", moduleName, err)
				} else {
					modules = append(modules, moduleName)
				}
			}
		}
	}
	log.Printf("Loaded %d MIB modules", len(modules))

	return nil
}
