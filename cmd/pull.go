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
	"text/template"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/zendesk/hyperclair/docker"
	"github.com/zendesk/hyperclair/xerrors"
)

const pullTplt = `
Image: {{.String}}
 {{.FsLayers | len}} layers found
 {{range .FsLayers}} ➜ {{.BlobSum}}
 {{end}}
`

const pullTplt_v2 = `
Image: {{.String}}
 {{.Layers | len}} layers found
 {{range .Layers}} ➜ {{.Digest}}
 {{end}}
`

// pingCmd represents the ping command
var pullCmd = &cobra.Command{
	Use:   "pull IMAGE",
	Short: "Pull Docker image information",
	Long:  `Pull image information from Docker Hub or Registry`,
	Run: func(cmd *cobra.Command, args []string) {
		//TODO how to use args with viper
		if len(args) != 1 {
			fmt.Printf("hyperclair: \"pull\" requires a minimum of 1 argument\n")
			os.Exit(1)
		}
		im := args[0]
		image, err := docker.Pull(im, insecureRegistry)
		if err != nil {
			fmt.Println(xerrors.ServiceUnavailable)
			logrus.Fatalf("pulling image %v: %v", args[0], err)
		}

		if image.SchemaVersion == 1 {
			err = template.Must(template.New("pull").Parse(pullTplt)).Execute(os.Stdout, image)
		} else {
			err = template.Must(template.New("pull").Parse(pullTplt_v2)).Execute(os.Stdout, image)
		}
		if err != nil {
			fmt.Println(xerrors.InternalError)
			logrus.Fatalf("rendering image: %v", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(pullCmd)
}
