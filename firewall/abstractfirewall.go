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

import "errors"

var FIREWALLD_CONFIGURATION = "firewalld"
var UFW_CONFIGURATION = "ufw"
var WINDOWS_FIREALL_CONFIGURATION = "windows_firewall"

type FirewallConfiguration interface {
	Initiliaze(credentials map[string]string) error
	AddPortForIP(ip, port string)
	LoadCurrentPolicy() error
	FlushNewPolicy() error
}

func CreateFirewall(credentials map[string]string, firewallType string) (FirewallConfiguration, error) {
	switch firewallType {
	case FIREWALLD_CONFIGURATION:
		firewall := &FirewallD{}
		err := firewall.Initiliaze(credentials)

		if err != nil {
			return nil, err
		}

		return firewall, nil
	case UFW_CONFIGURATION:
		firewall := &UFW{}
		err := firewall.Initiliaze(credentials)

		if err != nil {
			return nil, err
		}

		return firewall, nil
	case WINDOWS_FIREALL_CONFIGURATION:
		firewall := &WindowsFirewall{}
		err := firewall.Initiliaze(credentials)

		if err != nil {
			return nil, err
		}

		return firewall, nil
	default:
		return nil, errors.New("No such firewall type")
	}
}
