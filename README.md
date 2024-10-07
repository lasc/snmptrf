# SNMP Trap Receiver

This project implements an SNMP trap receiver that supports SNMPv2c and SNMPv3 traps and informs. It can handle different authentication methods and push notifications to various destinations such as v2 traps, Kafka, and RabbitMQ.

## Features

- Supports SNMPv2c and SNMPv3 traps and informs
- Handles different authentication methods for SNMPv3
- Capable of forwarding traps to multiple destinations:
  - v2 traps
  - Kafka
  - RabbitMQ

## Configuration

The configuration for the SNMP trap receiver is done through a JSON file named `config.json`. This file should be placed in the same directory as the executable. Here's an explanation of the configuration options:

## Usage

To run the SNMP trap receiver:

```
go run main.go
```

To send a test SNMP trap:

```
snmptrap -v 3 -a SHA -A authpass1 -x AES -X privpass1 -Ci -l authPriv -u user1 -e 0x8000000001020304 localhost:162 '' 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.5.0 s "Test v3 trap"
snmptrap -v 3 -a SHA -A authpass1 -x AES -X privpass1 -l authPriv -u user1 -e 0x8000000001020304 localhost:162 '' 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.5.0 s "Test v3 trap"
snmptrap -v 2c -c public localhost:162 '' 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.5.0 s "Test v2c trap"
```
