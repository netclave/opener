/*
 * Copyright @ 2020 - present Blackvisor Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package firewall

import (
	"fmt"
	"log"
	"strings"

	"github.com/netclave/common/utils"
)

type FirewallD struct {
	AddCommand            string
	RemoveCommand         string
	IPToPortsCurrentState map[string]map[string]bool
	IPToPortsNewState     map[string]map[string]bool
}

func (fd *FirewallD) Initiliaze(credentials map[string]string) error {
	fd.AddCommand = "firewall-cmd --zone=public --add-rich-rule='" +
		"rule family=\"ipv4\"" +
		" source address=\"{{ip}}\"" +
		" port protocol=\"{{protocol}}\" port=\"{{port}}\" accept'"

	fd.RemoveCommand = "firewall-cmd --zone=public --remove-rich-rule='" +
		" rule family=\"ipv4\"" +
		" source address=\"{{ip}}\"" +
		" port protocol=\"{{protocol}}\" port=\"{{port}}\" accept'"

	fd.IPToPortsCurrentState = map[string]map[string]bool{}
	fd.IPToPortsNewState = map[string]map[string]bool{}

	return nil
}

func (fd *FirewallD) AddPortForIP(ip, port string) {
	AddForIP(ip, port, &fd.IPToPortsNewState)
}

func (fd *FirewallD) ParseToken(token string) string {
	tokens := strings.Split(token, "=")
	return strings.Replace(tokens[1], "\"", "", -1)
}

func (fd *FirewallD) LoadCurrentPolicy() error {
	fd.IPToPortsCurrentState = map[string]map[string]bool{}

	//command := "firewall-cmd --zone=public --list-all | grep \"rule family\""

	command := "firewall-cmd --zone=public --list-all | grep rule"

	output, err := utils.RunCommandGetOutput(command)

	//output, err := runPipeCommand("firewall-cmd", "--zone=public --list-all", "grep", "\"rule family\"")

	if err != nil {
		log.Println(err.Error())
		return err
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if line != "" {
			if strings.Contains(strings.ToLower(line), "reject") == true {
				continue
			}

			fmt.Println("Loading rule: " + line)

			tokens := strings.Split(line, " ")
			address := ""
			protocol := ""
			port := ""
			for _, token := range tokens {
				if strings.Contains(token, "address=") == true {
					address = fd.ParseToken(token)
				}

				if strings.Contains(token, "port=") == true {
					port = fd.ParseToken(token)
				}

				if strings.Contains(token, "protocol=") == true {
					protocol = fd.ParseToken(token)
				}
			}

			fmt.Println(address + " " + port + " " + protocol)

			if address != "" && protocol != "" && port != "" {
				_, ok := fd.IPToPortsCurrentState[address]
				if ok == false {
					fd.IPToPortsCurrentState[address] = map[string]bool{}
				}

				fd.IPToPortsCurrentState[address][protocol+":"+port] = true
			}
		}
	}
	return nil
}

func (fd *FirewallD) FlushNewPolicy() error {
	return FlushNewPolicy(&fd.IPToPortsCurrentState, &fd.IPToPortsNewState, fd.AddCommand, fd.RemoveCommand)
}
