package docker

import (
	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/api/v1"
	"github.com/zendesk/hyperclair/clair"
	"github.com/zendesk/hyperclair/xstrings"
)

//Analyse return Clair Image analysis
func Analyse(image Image) clair.ImageAnalysis {
	res := []v1.LayerEnvelope{}

	layers := image.Layers
	if image.SchemaVersion == 1 {
		layers = image.FsLayers
	}

	c := len(layers)

	for i := range layers {

		l := layers[c-i-1].BlobSum

		if image.SchemaVersion != 1 {
			l = layers[c-i-1].Digest
		}

		lShort := xstrings.Substr(l, 0, 12)

		if a, err := clair.Analyse(l); err != nil {
			logrus.Infof("analysing layer [%v] %d/%d: %v", lShort, i+1, c, err)
		} else {
			logrus.Infof("analysing layer [%v] %d/%d", lShort, i+1, c)
			res = append(res, a)
		}
	}
	return clair.ImageAnalysis{
		Registry:  xstrings.TrimPrefixSuffix(image.Registry, "http://", "/v2"),
		ImageName: image.Name,
		Tag:       image.Tag,
		Layers:    res,
	}
}
