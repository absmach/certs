// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"net"
	"os"

	"gopkg.in/yaml.v2"
)

type CAConfig struct {
	CommonName         string   `yaml:"common_name"`
	Organization       []string `yaml:"organization"`
	OrganizationalUnit []string `yaml:"organizational_unit"`
	Country            []string `yaml:"country"`
	Province           []string `yaml:"province"`
	Locality           []string `yaml:"locality"`
	StreetAddress      []string `yaml:"street_address"`
	PostalCode         []string `yaml:"postal_code"`
	DNSNames           []string `yaml:"dns_names"`
	IPAddresses        []string `yaml:"ip_addresses"`
	ValidityPeriod     string   `yaml:"validity_period"`
}

func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config CAConfig
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &Config{
		CommonName:         config.CommonName,
		Organization:       config.Organization,
		OrganizationalUnit: config.OrganizationalUnit,
		Country:            config.Country,
		Province:           config.Province,
		Locality:           config.Locality,
		StreetAddress:      config.StreetAddress,
		PostalCode:         config.PostalCode,
		DNSNames:           config.DNSNames,
		IPAddresses:        parseIPs(config.IPAddresses),
	}, nil
}

func parseIPs(ipStrings []string) []net.IP {
	var ips []net.IP
	for _, ipString := range ipStrings {
		if ip := net.ParseIP(ipString); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
