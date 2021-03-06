// Copyright © 2016 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zendesk/hyperclair/config"
)

var cfgFile string
var logLevel string

// Format Docker Registry URL
func fmtRegistryURI(u string, insecure bool) (uri string) {
	uri = u
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		if insecure {
			uri = "http://" + uri
		} else {
			uri = "https://" + uri
		}
	}
	return uri
}

// Insecure registry var
var insecureRegistry bool

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "hyperclair",
	Short: "Analyse your docker image with Clair, directly from your registry.",
	Long:  ``,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) {
	// },
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.hyperclair.yml)")
	RootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "log level [Panic,Fatal,Error,Warn,Info,Debug]")
	RootCmd.PersistentFlags().BoolVar(&insecureRegistry, "insecure-registry", false, "Use http instead of https if supplied")
}

func initConfig() {
	config.Init(cfgFile, logLevel)
}
