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
	"log"
	"strings"
)

type UFW struct {
	AddCommand            string
	RemoveCommand         string
	IPToPortsCurrentState map[string]map[string]bool
	IPToPortsNewState     map[string]map[string]bool
}

func (ufw *UFW) Initiliaze(credentials map[string]string) error {
	ufw.AddCommand = "ufw allow from {{ip}} proto {{protocol}} to any port {{port}}"
	ufw.RemoveCommand = "ufw delete allow from {{ip}} proto {{protocol}} to any port {{port}}"

	ufw.IPToPortsCurrentState = map[string]map[string]bool{}
	ufw.IPToPortsNewState = map[string]map[string]bool{}

	return nil
}

func (ufw *UFW) AddPortForIP(ip, port string) {
	AddForIP(ip, port, &ufw.IPToPortsNewState)
}

func (ufw *UFW) ParseToken(token string) string {
	tokens := strings.Split(token, "=")
	return strings.Replace(tokens[1], "\"", "", -1)
}

func (ufw *UFW) LoadCurrentPolicy() error {
	ufw.IPToPortsCurrentState = map[string]map[string]bool{}

	//command := "firewall-cmd --zone=public --list-all | grep \"rule family\""

	command := "ufw status | grep ALLOW"

	output, err := runCommandGetOutput(command)

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

			for cc := 20; cc > 0; cc-- {
				replace := ""
				for ttt := 0; ttt < cc; ttt++ {
					replace += " "
				}

				line = strings.Replace(line, replace, " ", -1)
			}

			log.Println("Loading rule: " + line)

			tokens := strings.Split(line, " ")
			address := tokens[2]
			tokens1 := strings.Split(tokens[0], "/")
			protocol := tokens1[1]
			port := tokens1[0]

			//System.out.println(address + " " + port + " " + protocol);

			if address != "" && protocol != "" && port != "" {
				_, ok := ufw.IPToPortsCurrentState[address]
				if ok == false {
					ufw.IPToPortsCurrentState[address] = map[string]bool{}
				}

				ufw.IPToPortsCurrentState[address][protocol+":"+port] = true
			}
		}
	}

	return nil
}

func (ufw *UFW) FlushNewPolicy() error {
	return FlushNewPolicy(&ufw.IPToPortsCurrentState, &ufw.IPToPortsNewState, ufw.AddCommand, ufw.RemoveCommand)
}
