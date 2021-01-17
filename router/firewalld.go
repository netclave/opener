package router

import (
	"log"
	"strconv"
	"strings"

	"github.com/netclave/common/utils"
)

type FirewallDRouter struct {
	AddCommand       string
	RemoveCommand    string
	EnableMasquarade string
}

func (fdr *FirewallDRouter) Initiliaze(credentials map[string]string) error {
	fdr.AddCommand = "firewall-cmd --zone=public --add-forward-port=port={{fromPort}}:proto=tcp:toport={{toPort}}:toaddr={{ipAddress}}"

	fdr.RemoveCommand = "firewall-cmd --zone=public --remove-forward-port=port={{fromPort}}:proto=tcp:toport={{toPort}}:toaddr={{ipAddress}}"

	fdr.EnableMasquarade = "firewall-cmd --zone=public --add-masquerade"

	output, err := utils.RunCommandGetOutput(fdr.EnableMasquarade)

	if err != nil {
		log.Println(output)
		log.Println(err.Error())
		return err
	}

	return nil
}

func (fdr *FirewallDRouter) ExecuteRule(rule RouterRule) error {
	command := fdr.AddCommand

	command = strings.Replace(command, "{{fromPort}}", strconv.Itoa(rule.FromPort), -1)
	command = strings.Replace(command, "{{toPort}}", strconv.Itoa(rule.ToPort), -1)
	command = strings.Replace(command, "{{ipAddress}}", rule.IPAddress, -1)

	output, err := utils.RunCommandGetOutput(command)

	if err != nil {
		log.Println(output)
		log.Println(err.Error())
		return err
	}

	return nil
}
