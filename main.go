package main
// lasc
import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/gosnmp/gosnmp"
)

var (
	config      *Config
	SnmpConfigs map[string]*gosnmp.GoSNMP
)

func main() {
	// Parse command-line flags
	configFile := flag.String("config", "config.json", "Path to the configuration file")
	flag.Parse()

	// Load configuration
	var err error
	config, err = LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Error loading config: %s", err)
	}

	log.Printf("Loaded configuration: Target=%s, Port=%d, Users=%d", config.Target, config.Port, len(config.Users))

	// Initialize MIBs
	err = initMIBs(config.MIBDirs)
	if err != nil {
		log.Printf("Warning: Failed to initialize MIBs: %v", err)
	}

	// Configure gosnmp.Default
	configureSnmpSettings(config)

	// Initialize forwarder
	err = initForwarder()
	if err != nil {
		log.Printf("Error initializing forwarder: %v", err)
	}

	// Start UDP listener
	address := fmt.Sprintf("%s:%d", config.Target, config.Port)
	startUDPListener(address)

	// Keep the main goroutine running
	select {}

	if forwarder != nil {
		defer forwarder.Conn.Close()
	}
}

func configureSnmpSettings(config *Config) error {
	SnmpConfigs = make(map[string]*gosnmp.GoSNMP)

	// Add configurations for community strings
	for _, community := range config.CommunityStrings {
		SnmpConfigs[community] = &gosnmp.GoSNMP{
			Version:   gosnmp.Version2c,
			Community: community,
		}
		log.Printf("DEBUG: Configured SNMP for community: %s", community)
	}

	for _, user := range config.Users {
		snmpConfig := &gosnmp.GoSNMP{
			SecurityModel: gosnmp.UserSecurityModel,
			MsgFlags:      gosnmp.AuthPriv,
			Version:       gosnmp.Version3,
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 user.Username,
				AuthenticationProtocol:   getAuthProtocol(user.AuthProtocol),
				AuthenticationPassphrase: user.AuthPassphrase,
				PrivacyProtocol:          getPrivacyProtocol(user.PrivacyProtocol),
				PrivacyPassphrase:        user.PrivacyPassphrase,
			},
		}
		SnmpConfigs[user.Username] = snmpConfig

		// Add debug logging
		log.Printf("DEBUG: Configured SNMP for user: %s", user.Username)
		log.Printf("  AuthProtocol: %v", snmpConfig.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationProtocol)
		log.Printf("  PrivProtocol: %v", snmpConfig.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyProtocol)
		log.Printf("  AuthPassphrase: %s", snmpConfig.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationPassphrase)
		log.Printf("  PrivPassphrase: %s", snmpConfig.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyPassphrase)

		// Ensure the passphrases are set
		usmParams := snmpConfig.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if usmParams.AuthenticationPassphrase == "" {
			usmParams.AuthenticationPassphrase = user.AuthPassphrase
		}
		if usmParams.PrivacyPassphrase == "" {
			usmParams.PrivacyPassphrase = user.PrivacyPassphrase
		}

		SnmpConfigs[user.Username] = snmpConfig
	}

	log.Printf("Configured SNMP settings for %d users and %d communities", len(config.Users), len(config.CommunityStrings))
	return nil
}

func getAuthProtocol(protocol string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToLower(protocol) {
	case "md5":
		return gosnmp.MD5
	case "sha":
		return gosnmp.SHA
	case "sha224":
		return gosnmp.SHA224
	case "sha256":
		return gosnmp.SHA256
	case "sha384":
		return gosnmp.SHA384
	case "sha512":
		return gosnmp.SHA512
	default:
		log.Printf("WARNING: Unknown auth protocol %s, defaulting to SHA", protocol)
		return gosnmp.SHA
	}
}

func getPrivacyProtocol(protocol string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToLower(protocol) {
	case "des":
		return gosnmp.DES
	case "aes":
		return gosnmp.AES
	case "aes192":
		return gosnmp.AES192
	case "aes256":
		return gosnmp.AES256
	default:
		log.Printf("WARNING: Unknown privacy protocol %s, defaulting to AES", protocol)
		return gosnmp.AES
	}
}
