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
)

type WindowsFirewall struct {
	AddCommand            string
	RemoveCommand         string
	IPToPortsCurrentState map[string]map[string]bool
	IPToPortsNewState     map[string]map[string]bool
}

func (wf *WindowsFirewall) Initiliaze(credentials map[string]string) error {
	wf.AddCommand = "netsh advfirewall firewall add rule name=\"Open port:{{port}} for ip:{{ip}} with protocol:{{protocol}} by NetClave\" dir=in action=allow protocol={{protocol}} localport={{port}} remoteip={{ip}}"
	wf.RemoveCommand = "netsh advfirewall firewall delete rule name=\"Open port:{{port}} for ip:{{ip}} with protocol:{{protocol}} by NetClave\" protocol={{protocol}} localport={{port}} remoteip={{ip}}"

	wf.IPToPortsCurrentState = map[string]map[string]bool{}
	wf.IPToPortsNewState = map[string]map[string]bool{}

	return nil
}

func (wf *WindowsFirewall) AddPortForIP(ip, port string) {
	AddForIP(ip, port, &wf.IPToPortsNewState)
}

func (wf *WindowsFirewall) ParseToken(token string) string {
	tokens := strings.Split(token, ":")
	return tokens[1]
}

func (wf *WindowsFirewall) LoadCurrentPolicy() error {
	wf.IPToPortsCurrentState = map[string]map[string]bool{}

	//command := "firewall-cmd --zone=public --list-all | grep \"rule family\""

	command := "netsh advfirewall firewall show rule name=all | find \"Rule Name:\" | find \"NetClave\""

	output, err := runCommandGetOutput(command)

	//output, err := runPipeCommand("firewall-cmd", "--zone=public --list-all", "grep", "\"rule family\"")

	if err != nil {
		log.Println(err.Error())
		return err
	}

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if line != "" {
			fmt.Println("Loading rule: " + line)

			tokens := strings.Split(line, " ")
			address := ""
			protocol := ""
			port := ""
			for _, token := range tokens {
				if strings.Contains(token, "ip:") == true {
					address = wf.ParseToken(token)
				}

				if strings.Contains(token, "port:") == true {
					port = wf.ParseToken(token)
				}

				if strings.Contains(token, "protocol:") == true {
					protocol = wf.ParseToken(token)
				}
			}

			fmt.Println(address + " " + port + " " + protocol)

			if address != "" && protocol != "" && port != "" {
				_, ok := wf.IPToPortsCurrentState[address]
				if ok == false {
					wf.IPToPortsCurrentState[address] = map[string]bool{}
				}

				wf.IPToPortsCurrentState[address][protocol+":"+port] = true
			}
		}
	}
	return nil
}

func (wf *WindowsFirewall) FlushNewPolicy() error {
	return FlushNewPolicy(&wf.IPToPortsCurrentState, &wf.IPToPortsNewState, wf.AddCommand, wf.RemoveCommand)
}
