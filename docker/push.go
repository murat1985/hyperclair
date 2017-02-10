package docker

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/api/v1"
	"github.com/zendesk/hyperclair/clair"
	"github.com/zendesk/hyperclair/config"
	"github.com/zendesk/hyperclair/database"
	"github.com/zendesk/hyperclair/xstrings"
)

//Push image to Clair for analysis
func Push(image Image) error {

	layerCount := len(image.FsLayers)
	if image.SchemaVersion != 1 {
		layerCount = len(image.Layers)
	}

	parentID := ""

	if layerCount == 0 {
		logrus.Warningln("there is no layer to push")
	}
	localIP, err := config.LocalServerIP()
	if err != nil {
		return err
	}
	hURL := fmt.Sprintf("http://%v/v2", localIP)
	if IsLocal {
		hURL = strings.Replace(hURL, "/v2", "/local", -1)
		logrus.Infof("using %v as local url", hURL)
	}

	layers := image.Layers
	if image.SchemaVersion == 1 {
		layers = image.FsLayers
	}

	for index, layer := range layers {
		lUID := xstrings.Substr(layer.BlobSum, 0, 12)
		digest := layer.BlobSum

		if image.SchemaVersion != 1 {
			lUID = xstrings.Substr(layer.Digest, 0, 12)
			digest = layer.Digest
		}

		logrus.Infof("Pushing Layer %d/%d [%v]", index+1, layerCount, lUID)

		database.InsertRegistryMapping(digest, image.Registry)
		payload := v1.LayerEnvelope{Layer: &v1.Layer{
			Name:       digest,
			Path:       image.BlobsURI(digest),
			ParentName: parentID,
			Format:     "Docker",
		}}

		//FIXME Update to TLS
		if IsLocal {
			payload.Layer.Name = layer.History
			payload.Layer.Path += "/layer.tar"
		}
		payload.Layer.Path = strings.Replace(payload.Layer.Path, image.Registry, hURL, 1)
		if err := clair.Push(payload); err != nil {
			logrus.Infof("adding layer %d/%d [%v]: %v", index+1, layerCount, lUID, err)
			if err != clair.OSNotSupported {
				return err
			}
			parentID = ""
		} else {
			parentID = payload.Layer.Name
		}
	}
	if IsLocal {
		if err := cleanLocal(); err != nil {
			return err
		}
	}
	return nil
}
