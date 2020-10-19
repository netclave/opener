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

func AddForIP(ip, port string, state *map[string]map[string]bool) {
	_, ok := (*state)[ip]

	if ok == false {
		(*state)[ip] = map[string]bool{}
	}

	(*state)[ip][port] = true
}

func FlushNewPolicy(currentState, newState *map[string]map[string]bool, addCommand, removeCommand string) error {
	removeRules := map[string]map[string]bool{}
	addRules := map[string]map[string]bool{}

	for ip := range *currentState {
		_, ok := (*newState)[ip]

		if ok == false {
			currentPorts := (*currentState)[ip]

			_, okRemoveRules := removeRules[ip]

			if okRemoveRules == false {
				removeRules[ip] = map[string]bool{}
			}

			for port := range currentPorts {
				removeRules[ip][port] = true
			}
		}
	}

	for ip := range *newState {
		_, ok := (*currentState)[ip]

		if ok == true {
			currentPorts := (*currentState)[ip]
			newPorts, newPortsOk := (*newState)[ip]

			if newPortsOk == false {
				newPorts = map[string]bool{}
			}

			for currentPort := range currentPorts {
				_, newPortsOk := newPorts[currentPort]

				if newPortsOk == false {
					_, removeRulesOK := removeRules[ip]

					if removeRulesOK == false {
						removeRules[ip] = map[string]bool{}
					}

					removeRules[ip][currentPort] = true
				}
			}

			for newPort := range newPorts {
				_, currentPortsOK := currentPorts[newPort]

				if currentPortsOK == false {
					_, addRulesOK := addRules[ip]

					if addRulesOK == false {
						addRules[ip] = map[string]bool{}
					}

					addRules[ip][newPort] = true
				}
			}
		} else {
			newPorts, newPortsOk := (*newState)[ip]

			if newPortsOk == false {
				newPorts = map[string]bool{}
			}

			_, addRulesOK := addRules[ip]

			if addRulesOK == false {
				addRules[ip] = map[string]bool{}
			}

			for newPort := range newPorts {
				addRules[ip][newPort] = true
			}
		}
	}

	removeCommandStrings := []string{}

	for ip := range removeRules {
		fmt.Println("Removing ip: " + ip)
		for portPair := range removeRules[ip] {
			tt := strings.Split(portPair, ":")
			protocol := tt[0]
			port := tt[1]
			command := strings.Replace(removeCommand, "{{ip}}", ip, -1)
			command = strings.Replace(command, "{{protocol}}", protocol, -1)
			command = strings.Replace(command, "{{port}}", port, -1)
			removeCommandStrings = append(removeCommandStrings, command)
		}
	}

	addCommandStrings := []string{}

	for ip := range addRules {
		fmt.Println("Adding ip: " + ip)
		for portPair := range addRules[ip] {
			tt := strings.Split(portPair, ":")
			protocol := tt[0]
			port := tt[1]
			command := strings.Replace(addCommand, "{{ip}}", ip, -1)
			command = strings.Replace(command, "{{protocol}}", protocol, -1)
			command = strings.Replace(command, "{{port}}", port, -1)
			addCommandStrings = append(addCommandStrings, command)
		}
	}

	fmt.Println("Executing remove commands")

	for _, commandString := range removeCommandStrings {
		output, err := utils.RunCommandGetOutput(commandString)

		if err != nil {
			log.Println(err.Error())
			return err
		}

		fmt.Println(output)
	}

	fmt.Println("Executing add commands")

	for _, commandString := range addCommandStrings {

		output, err := utils.RunCommandGetOutput(commandString)

		if err != nil {
			log.Println(err.Error())
			return err
		}

		fmt.Println(output)
	}

	(*newState) = map[string]map[string]bool{}

	return nil
}
