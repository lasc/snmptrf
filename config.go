package main

import (
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/gosnmp/gosnmp"
)

type SNMPUser struct {
    Username           string `json:"username"`
    AuthProtocol       string `json:"auth_protocol"`
    AuthPassphrase     string `json:"auth_passphrase"`
    PrivacyProtocol    string `json:"privacy_protocol"`
    PrivacyPassphrase  string `json:"privacy_passphrase"`
}

type OutputConfig struct {
	LogFile        string `json:"log_file"`
	AuthFailureLog string `json:"auth_failure_log"`
}

type Config struct {
	Target           string       `json:"target"`
	Port             uint16       `json:"port"`
	Users            []SNMPUser   `json:"users"`
	CommunityStrings []string     `json:"community_strings"`
	Output           struct {
		LogFile        string `json:"log_file"`
		AuthFailureLog string `json:"auth_failure_log"`
	} `json:"output"`
	Kafka struct {
		Enabled bool     `json:"enabled"`
		Brokers []string `json:"brokers"`
		Topic   string   `json:"topic"`
	} `json:"kafka"`
	RabbitMQ struct {
		Enabled    bool   `json:"enabled"`
		URL        string `json:"url"`
		Exchange   string `json:"exchange"`
		RoutingKey string `json:"routing_key"`
	} `json:"rabbitmq"`
	ForwardTarget struct {
		Enabled   bool   `json:"enabled"`
		Address   string `json:"address"`
		Port      int    `json:"port"`
		Community string `json:"community"`
	} `json:"forward_target"`
	MIBDirs []string `json:"mib_dirs"`
}

// ... (keep the existing type definitions)

func LoadConfig(filename string) (*Config, error) {
	log.Printf("Loading configuration from %s", filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// Set default log file if not specified
	if config.Output.LogFile == "" {
		config.Output.LogFile = "snmp_messages.log"
	}

	log.Printf("Configuration loaded successfully")
	return &config, nil
}

func (u *SNMPUser) ToUsmSecurityParameters() *gosnmp.UsmSecurityParameters {
    return &gosnmp.UsmSecurityParameters{
        UserName:                 u.Username,
        AuthenticationProtocol:   getAuthProtocol(u.AuthProtocol),
        AuthenticationPassphrase: u.AuthPassphrase,
        PrivacyProtocol:          getPrivProtocol(u.PrivacyProtocol),
        PrivacyPassphrase:        u.PrivacyPassphrase,
    }
}


func getPrivProtocol(protocol string) gosnmp.SnmpV3PrivProtocol {
	log.Printf("DEBUG: Getting privacy protocol for: %s", protocol)
	switch protocol {
	case "AES":
		return gosnmp.AES
	case "DES":
		return gosnmp.DES
	default:
		log.Printf("WARNING: Unknown privacy protocol: %s, defaulting to NoPriv", protocol)
		return gosnmp.NoPriv
	}
}

func (c *Config) getUserByName(username string) (*SNMPUser, bool) {
	for _, user := range c.Users {
		if user.Username == username {
			return &user, true
		}
	}
	return nil, false
}
