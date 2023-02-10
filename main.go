package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	ocistatic "github.com/google/go-containerregistry/pkg/v1/static"
	ocitypes "github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	spdxType      = "text/spdx+json"
	cyclonedxType = "application/vnd.cyclonedx+json"
	syftType      = "application/vnd.syft+json"
)

func findMediaType(fileName string) ocitypes.MediaType {
	switch {
	case strings.Contains(fileName, "spdx.json"):
		return ocitypes.MediaType(spdxType)
	case strings.Contains(fileName, "cdx.json"):
		return ocitypes.MediaType(cyclonedxType)
	case strings.Contains(fileName, "syft.json"):
		return ocitypes.MediaType(syftType)
	default:
		return ocitypes.OCIConfigJSON
	}

}

func main() {

	var dig name.Digest
	ref, err := name.ParseReference(os.Args[1])
	if err != nil {
		panic(err)
	}

	if digr, ok := ref.(name.Digest); ok {
		dig = digr
	} else {
		desc, err := remote.Head(ref)
		if err != nil {
			panic(err)
		}
		dig = ref.Context().Digest(desc.Digest.String())
	}
	desc, err := remote.Head(dig)
	if err != nil {
		panic(err)
	}

	artifactType := "application/vnd.dev.cosign.artifact.sbom.v1+json"

	var terr *transport.Error
	if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
		h, err := v1.NewHash(dig.DigestStr())
		if err != nil {
			panic(err)
		}
		desc = &v1.Descriptor{
			ArtifactType: "application/vnd.dev.cosign.artifact.sbom.v1+json",
			MediaType:    ocitypes.OCIManifestSchema1,
			Size:         0,
			Digest:       h,
		}
	} else if err != nil {
		panic(err)
	}

	empty := mutate.MediaType(
		mutate.ConfigMediaType(empty.Image, ocitypes.MediaType(artifactType)),
		ocitypes.OCIManifestSchema1)

	jsonFiles, err := findJSONFiles(os.Args[2])
	if err != nil {
		panic(err)
	}

	newImg, err := AddSBOMLayers(empty, jsonFiles)
	if err != nil {
		panic(err)
	}

	newImg = mutate.Subject(newImg, *desc).(v1.Image)
	newImgDig, err := newImg.Digest()
	if err != nil {
		panic(err)
	}

	dstRef := ref.Context().Digest(newImgDig.String())
	log.Info(fmt.Sprintf("Pushing %s", dstRef.String()))
	err = remote.Write(dstRef, newImg)
	if err != nil {
		panic(err)
	}

	log.Info(fmt.Sprintf("Pushed %s", dstRef.String()))
}

func AddSBOMLayers(img v1.Image, sbomFiles []string) (v1.Image, error) {
	layers := make([]v1.Layer, 0, len(sbomFiles))
	for _, sbomFile := range sbomFiles {
		b, err := os.ReadFile(sbomFile)
		if err != nil {
			return nil, err
		}

		layers = append(layers, ocistatic.NewLayer(b, findMediaType(sbomFile)))
	}

	newImg, err := mutate.AppendLayers(img, layers...)
	if err != nil {
		return nil, err
	}

	return newImg, nil
}

func findJSONFiles(root string) ([]string, error) {
	var results []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if filepath.Ext(path) == ".json" {
			results = append(results, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return results, nil
}
