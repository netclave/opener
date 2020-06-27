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

package config

import (
	"bufio"
	"flag"
	"log"
	"os"

	"github.com/netclave/opener/firewall"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/netclave/common/storage"
)

var DataStorageCredentials map[string]string
var StorageType string
var FirewallType string
var FirewallCredentials map[string]string

var ListenGRPCAddress = "localhost:6667"

func Init() error {
	flag.String("configFile", "~/config.json", "Provide full path to your config json file")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	filename := viper.GetString("configFile") // retrieve value from viper

	file, err := os.Open(filename)

	viper.SetConfigType("json")

	if err != nil {
		log.Println(err.Error())
	} else {
		err = viper.ReadConfig(bufio.NewReader(file))

		if err != nil {
			log.Println(err.Error())
			return err
		}
	}

	viper.SetDefault("host.grpcaddress", "localhost:6667")

	viper.SetDefault("datastorage.credentials", map[string]string{
		"host":     "localhost:6379",
		"db":       "5",
		"password": "",
	})
	viper.SetDefault("datastorage.type", storage.REDIS_STORAGE)

	viper.SetDefault("firewall.credentials", map[string]string{})

	viper.SetDefault("firewall.type", firewall.FIREWALLD_CONFIGURATION)

	hostConfig := viper.Sub("host")

	ListenGRPCAddress = hostConfig.GetString("grpcaddress")

	log.Println(ListenGRPCAddress)

	datastorageConfig := viper.Sub("datastorage")

	DataStorageCredentials = datastorageConfig.GetStringMapString("credentials")
	StorageType = datastorageConfig.GetString("type")

	firewallConfig := viper.Sub("firewall")

	FirewallCredentials = firewallConfig.GetStringMapString("credentials")
	FirewallType = firewallConfig.GetString("type")

	return err
}
