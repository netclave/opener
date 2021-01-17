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

package router

import "errors"

var ROUTER_FIREWALLD_CONFIGURATION = "firewalld"

type RouterRule struct {
	FromPort  int
	ToPort    int
	IPAddress string
}

type Router interface {
	Initiliaze(credentials map[string]string) error
	ExecuteRule(rule RouterRule) error
}

func CreateRouter(credentials map[string]string, routerType string) (Router, error) {
	switch routerType {
	case ROUTER_FIREWALLD_CONFIGURATION:
		router := &FirewallDRouter{}
		err := router.Initiliaze(credentials)

		if err != nil {
			return nil, err
		}

		return router, nil
	default:
		return nil, errors.New("No such router type")
	}
}
