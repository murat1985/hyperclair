package docker

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/viper"
	"github.com/zendesk/hyperclair/xerrors"
)

//Image represent Image Manifest from Docker image, including the registry URL

type Image struct {
	Name          string
	Tag           string
	Registry      string
	SchemaVersion int
	FsLayers      []Layer
	Layers        []Layer
}

// schema v1 layer represent the digest of a image layer
type Layer struct {
	BlobSum   string
	History   string
	MediaType string
	Size      int
	Digest    string
}

const dockerImageRegex = "^(?:([^/]+)/)?(?:(.+)/)*([^@:/]+)(?:[@:](.+))?"
const DockerHub = "registry-1.docker.io"
const hubURI = "https://" + DockerHub + "/v2"

var IsLocal = false

func TmpLocal() string {
	return viper.GetString("hyperclair.tempFolder")
}

// Parse is used to parse a docker image command
//
//Example:
//"register.com:5080/zendesk/alpine"
//"register.com:5080/zendesk/alpine:latest"
//"register.com:5080/alpine"
//"register.com/zendesk/alpine"
//"register.com/alpine"
//"register.com/zendesk/alpine:latest"
//"alpine"
//"zendesk/alpine"
//"zendesk/alpine:latest"
func Parse(image string, insecure bool) (Image, error) {
	imageRegex := regexp.MustCompile(dockerImageRegex)

	if imageRegex.MatchString(image) == false {
		return Image{}, fmt.Errorf("cannot parse image name: %v", image)
	}
	groups := imageRegex.FindStringSubmatch(image)

	registry, repository, name, tag := groups[1], groups[2], groups[3], groups[4]

	if tag == "" {
		tag = "latest"
	}

	if repository == "" && !strings.ContainsAny(registry, ":.") {
		repository, registry = registry, hubURI //Regex problem, if no registry in url, regex parse repository as registry, so need to invert it
	} else {
		if insecure {
			registry = "http://" + registry + "/v2"
		} else {
			registry = "https://" + registry + "/v2"
		}
	}

	if repository != "" {
		name = repository + "/" + name
	}

	if strings.Contains(registry, "docker.io") && repository == "" {
		return Image{}, xerrors.ErrDisallowed
	}

	return Image{
		Registry: registry,
		Name:     name,
		Tag:      tag,
	}, nil
}

// BlobsURI run Blobs URI as <registry>/<imageName>/blobs/<digest>
// eg: "http://registry:5000/v2/jgsqware/ubuntu-git/blobs/sha256:13be4a52fdee2f6c44948b99b5b65ec703b1ca76c1ab5d2d90ae9bf18347082e"
func (image Image) BlobsURI(digest string) string {
	return strings.Join([]string{image.Registry, image.Name, "blobs", digest}, "/")
}

func (image Image) String() string {
	return image.Registry + "/" + image.Name + ":" + image.Tag
}

func (image Image) AsJSON() (string, error) {
	b, err := json.Marshal(image)
	if err != nil {
		return "", fmt.Errorf("cannot marshal image: %v", err)
	}
	return string(b), nil
}
