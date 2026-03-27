package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	manifestList "github.com/docker/distribution/manifest/manifestlist"
	manifestV1 "github.com/docker/distribution/manifest/schema1"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httptrace"
	"github.com/neuvector/neuvector/share/scan/registry"
)

const (
	mediaTypeCosign            = "application/vnd.dev.cosign.simplesigning.v1+json"
	mediaTypeInTotoAttestation = "application/vnd.dsse.envelope.v1+json"
	mediaTypeSPDX              = "application/spdx+json"
	mediaTypeCycloneDX         = "application/vnd.cyclonedx+json"
	mediaTypeHelmChart         = "application/vnd.cncf.helm.chart.v1+json"
	quayRegistryURL            = "https://quay.io"
	cosignSignatureTagSuffix   = ".sig"
)

var (
	hostOS   = runtime.GOOS
	hostArch = runtime.GOARCH
)

type RegClient struct {
	*registry.Registry
}

// If token is given, the Authorization header will be added with token appended.
func NewRegClient(url, token, username, password, proxy string, trace httptrace.HTTPTrace) *RegClient {
	log.WithFields(log.Fields{"url": url}).Debug("")

	// Ignore errors
	hub, _, _ := registry.New(url, token, username, password, proxy, trace)
	return &RegClient{Registry: hub}
}

type ImageInfo struct {
	Layers           []string
	ID               string
	Digest           string
	Author           string
	Signed           bool
	RunAsRoot        bool
	Created          time.Time
	Envs             []string
	Cmds             []string
	Labels           map[string]string
	Sizes            map[string]int64
	RepoTags         []string
	IsSignatureImage bool
	RawManifest      []byte
	SignatureDigest  string
}

func isImageManifestMediaType(mt string) bool {
	// Explicitly skip known non-image artifact types
	switch mt {
	case mediaTypeCosign, // Cosign signature
		mediaTypeInTotoAttestation, // In-toto attestation
		mediaTypeSPDX,              // SBOM (SPDX)
		mediaTypeCycloneDX,         // SBOM (CycloneDX)
		mediaTypeHelmChart:         // Helm Chart
		return false
	}

	// Accept standard image manifest types
	if mt == manifestV2.MediaTypeManifest || mt == registry.MediaTypeOCIManifest || mt == "" {
		return true
	}
	return false
}

// helper: rank a platform descriptor based on how well it matches our host
func platformRank(os, arch string) int {
	// 0 = best, higher = worse
	if os == hostOS && arch == hostArch {
		return 0 // exact match (e.g. linux/arm64 on arm64 host)
	}
	if os == "linux" && arch == "amd64" {
		return 1 // preferred fallback
	}
	if os == "linux" {
		return 2 // other linux architectures
	}
	return 3 // non-linux
}

func isPotentialCosignSignatureTag(tag string) bool {
	return (strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, cosignSignatureTagSuffix))
}

func isQuayRegistry(rc *RegClient) bool {
	if len(rc.URL) >= len(quayRegistryURL) {
		return strings.EqualFold(rc.URL[:len(quayRegistryURL)], quayRegistryURL)
	}
	return false
}

func isCosignPayload(mediaType string) bool {
	return mediaType == mediaTypeCosign || mediaType == mediaTypeInTotoAttestation
}

func copyV2Layers(imageInfo *ImageInfo, manV2 *manifestV2.Manifest, ccmi *registry.ManifestInfo) bool {
	allLayersAreCosignPayloads := true

	// In the history list from container image config spec, only the layer that has no empty_layer flag
	// has a digest in the manifest layer list.
	// The following section bring the layer list in imageInfo to the same size as history (cmd)
	if ccmi != nil {
		j := len(manV2.Layers) - 1
		for i := 0; i < len(ccmi.Cmds); i++ {
			if ccmi.EmptyLayers[i] || j < 0 {
				imageInfo.Layers = append(imageInfo.Layers, "")
			} else {
				layer := manV2.Layers[j]
				imageInfo.Layers = append(imageInfo.Layers, string(layer.Digest))
				imageInfo.Sizes[string(layer.Digest)] = layer.Size
				if !isCosignPayload(layer.MediaType) {
					allLayersAreCosignPayloads = false
				}

				j--
			}
		}
	} else {
		for j := len(manV2.Layers) - 1; j >= 0; j-- {
			layer := manV2.Layers[j]
			imageInfo.Layers = append(imageInfo.Layers, string(layer.Digest))
			imageInfo.Sizes[string(layer.Digest)] = layer.Size
			if !isCosignPayload(layer.MediaType) {
				allLayersAreCosignPayloads = false
			}
		}
	}

	return allLayersAreCosignPayloads
}

func (rc *RegClient) buildV2ImageInfo(imageInfo *ImageInfo, ctx context.Context, name, dg string, body []byte) (
	parsedSchemaVersion int, configMediaType string, err error,
) {
	var manV2 manifestV2.Manifest

	err = json.Unmarshal(body, &manV2)
	if err != nil {
		return manV2.SchemaVersion, "", err
	}
	if manV2.SchemaVersion != 2 {
		return manV2.SchemaVersion, "", fmt.Errorf("unexpected manifest schema version: %d", manV2.SchemaVersion)
	}

	// use v2 config.Digest as repo id
	imageInfo.ID = string(manV2.Config.Digest)
	imageInfo.Digest = dg

	var ccmi *registry.ManifestInfo
	if manV2.Config.MediaType == registry.MediaTypeContainerImage ||
		manV2.Config.MediaType == registry.MediaTypeOCIImageConfig {
		if ccmi, err = rc.ImageConfigSpecV1(ctx, name, manV2.Config.Digest); err == nil {
			imageInfo.Cmds = ccmi.Cmds
			imageInfo.Envs = ccmi.Envs
			imageInfo.Labels = ccmi.Labels
			imageInfo.Created = ccmi.Created
		}
	}

	imageInfo.IsSignatureImage = copyV2Layers(imageInfo, &manV2, ccmi)

	log.WithFields(log.Fields{
		"mediaType": manV2.Config.MediaType, "version": manV2.SchemaVersion, "digest": dg,
		"layers": len(manV2.Layers), "cmds": len(imageInfo.Cmds), "created": imageInfo.Created,
	}).Debug("v2 manifest")

	return manV2.SchemaVersion, manV2.Config.MediaType, nil
}

func (rc *RegClient) GetImageInfo(ctx context.Context, name, tag string, manifestReqType registry.ManifestRequestType) (*ImageInfo, share.ScanErrorCode) {
	if manifestReqType == registry.ManifestRequest_CosignSignature {
		log.WithFields(log.Fields{"name": name, "tag": tag}).Debug("retrieving signature information")
	}

	var dg string
	var body []byte
	var err error
	var isQuaySpecialCase = false

	imageInfo := &ImageInfo{
		Layers: make([]string, 0),
		Envs:   make([]string, 0),
		Cmds:   make([]string, 0),
		Labels: make(map[string]string),
		Sizes:  make(map[string]int64),
	}

	if isPotentialCosignSignatureTag(tag) && isQuayRegistry(rc) {
		dg, body, err = rc.ManifestRequest(ctx, name, tag, 2, registry.ManifestRequest_CosignSignature)
		if err == nil {
			_, _, err = rc.buildV2ImageInfo(imageInfo, ctx, name, dg, body)
			if err == nil {
				isQuaySpecialCase = true
			} else {
				imageInfo = &ImageInfo{
					Layers: make([]string, 0),
					Envs:   make([]string, 0),
					Cmds:   make([]string, 0),
					Labels: make(map[string]string),
					Sizes:  make(map[string]int64),
				}
			}
		}
	}

	var v2SchemaError error = nil
	if !isQuaySpecialCase {
		if manifestReqType == registry.ManifestRequest_CosignSignature {
			log.WithFields(log.Fields{"name": name, "tag": tag}).Debug("not quay special case, trying v2")
		}
		dg, body, err = rc.ManifestRequest(ctx, name, tag, 2, manifestReqType)
		if err == nil {
			// check if response is manifest list
			var ml manifestList.DeserializedManifestList
			if err = ml.UnmarshalJSON(body); err == nil && len(ml.Manifests) > 0 &&
				(ml.MediaType == manifestList.MediaTypeManifestList || ml.MediaType == registry.MediaTypeOCIIndex) {
				log.WithFields(log.Fields{"name": name, "tag": tag}).Debug("manifest request result is manifest list")

				// Filter to only entries that look like image manifests (not SBOMs, signatures, attestations, etc.)
				imageDescs := make([]manifestList.ManifestDescriptor, 0, len(ml.Manifests))
				for _, desc := range ml.Manifests {
					if isImageManifestMediaType(desc.MediaType) {
						imageDescs = append(imageDescs, desc)
					}
				}

				if len(imageDescs) == 0 {
					log.WithFields(log.Fields{"name": name, "tag": tag}).Error("manifest list has no image manifests")
					// fall through – v2SchemaError/v1 may handle
				} else {
					sort.Slice(imageDescs, func(i, j int) bool {
						ri := platformRank(imageDescs[i].Platform.OS, imageDescs[i].Platform.Architecture)
						rj := platformRank(imageDescs[j].Platform.OS, imageDescs[j].Platform.Architecture)
						if ri != rj {
							return ri < rj
						}
						// tie‑breaker: stable-ish ordering
						return imageDescs[i].Platform.Architecture < imageDescs[j].Platform.Architecture
					})

					chosen := imageDescs[0]
					tag = string(chosen.Digest)
					dg = tag
					log.WithFields(log.Fields{
						"os":        chosen.Platform.OS,
						"arch":      chosen.Platform.Architecture,
						"tag":       tag,
						"host_os":   hostOS,
						"host_arch": hostArch,
					}).Debug("manifest list: selected platform image")

					_, body, err = rc.ManifestRequest(ctx, name, tag, 2, manifestReqType)
				}
			}
		} else {
			v2SchemaError = fmt.Errorf("error when requesting v2 manifest, will try v1: %s", err.Error())
		}

		// get schema v2 first
		if err == nil {
			var parsedSchemaVersion int
			var cfgMediaType string

			parsedSchemaVersion, cfgMediaType, err = rc.buildV2ImageInfo(imageInfo, ctx, name, dg, body)
			if err != nil {
				v2SchemaError = fmt.Errorf("could not build v2 image info, will try v1: %s", err.Error())
				log.WithFields(log.Fields{"error": err, "schema": parsedSchemaVersion}).Debug("Failed to get manifest schema v2")
			}

			// Check if this is a container image we can scan
			isContainerImage := (cfgMediaType == registry.MediaTypeContainerImage ||
				cfgMediaType == registry.MediaTypeOCIImageConfig ||
				cfgMediaType == "")

			if !isContainerImage {
				log.WithFields(log.Fields{
					"mediaType": cfgMediaType,
					"name":      name,
					"tag":       tag,
				}).Info("Skipping non-image artifact (Helm chart, signature, attestation, or SBOM)")
				return imageInfo, share.ScanErrorCode_ScanErrImageNotFound
			}
		}
	}

	if v2SchemaError != nil {
		log.WithFields(log.Fields{"name": name, "tag": tag, "error": v2SchemaError.Error()}).Error("could not build v2 image info, trying v1")
		// get schema v1
		manV1, err := rc.Manifest(ctx, name, tag)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Debug("Get Manifest v1 fail")
		} else {
			log.WithFields(log.Fields{
				"mediaType": manV1.SignedManifest.MediaType, "version": manV1.SignedManifest.SchemaVersion, "digest": manV1.Digest,
				"layers": len(manV1.SignedManifest.FSLayers), "cmds": len(manV1.Cmds), "created": manV1.Created,
			}).Debug("v1 manifest")

			// Even we send request with accept v1 manifest, we still get v2 format back
			if manV1.SignedManifest.SchemaVersion <= 1 {
				if len(manV1.SignedManifest.FSLayers) > 0 {
					imageInfo.Layers = make([]string, len(manV1.SignedManifest.FSLayers))
					for i, des := range manV1.SignedManifest.FSLayers {
						imageInfo.Layers[i] = string(des.BlobSum)
						// log.WithFields(log.Fields{"i": i, "layer": string(des.BlobSum)}).Debug("v1 manifest")
					}
				}

				// no config in v1, use the latest layer id as the repo id
				if imageInfo.ID == "" {
					imageInfo.ID = rc.getSchemaV1Id(manV1.SignedManifest)
					if imageInfo.ID == "" && len(manV1.SignedManifest.FSLayers) > 0 {
						imageInfo.ID = string(manV1.SignedManifest.FSLayers[0].BlobSum)
					}
				}
				if imageInfo.Digest == "" {
					imageInfo.Digest = manV1.Digest
				}

				// comment out because it's not an accurate way to tell it's signed
				/*if sigs, err := manV1.Signatures(); err == nil && len(sigs) > 0 {
					signed = true
				}*/

				// Prefer data from manifest v2, in some image, cmds in manV1 has incomplete data
				if len(imageInfo.Envs) == 0 {
					imageInfo.Envs = manV1.Envs
				}
				if len(imageInfo.Cmds) == 0 {
					imageInfo.Cmds = manV1.Cmds
				}
				if len(imageInfo.Labels) == 0 {
					imageInfo.Labels = manV1.Labels
				}
				// Prefer Author from manifest v1
				if manV1.Author != "" {
					imageInfo.Author = manV1.Author
				}
				if manV1.Created.After(imageInfo.Created) {
					imageInfo.Created = manV1.Created
				}
			}
		}
	}

	if strings.HasPrefix(imageInfo.ID, "sha") {
		if i := strings.Index(imageInfo.ID, ":"); i > 0 {
			imageInfo.ID = imageInfo.ID[i+1:]
		}
	}
	if imageInfo.ID == "" || len(imageInfo.Layers) == 0 {
		if manifestReqType == registry.ManifestRequest_CosignSignature {
			log.WithFields(log.Fields{"name": name, "tag": tag}).Debug("Signature information could not be found")
			return imageInfo, share.ScanErrorCode_ScanErrNone
		}
		log.WithFields(log.Fields{"imageInfo": imageInfo}).Error("Get metadata fail")

		if imageInfo.ID == "" {
			return imageInfo, share.ScanErrorCode_ScanErrImageNotFound
		} else {
			return imageInfo, share.ScanErrorCode_ScanErrRegistryAPI
		}
	}

	for i, c := range imageInfo.Cmds {
		imageInfo.Cmds[i] = NormalizeImageCmd(c)
	}
	runAsRoot, _, _ := ParseImageCmds(imageInfo.Cmds)
	imageInfo.RunAsRoot = runAsRoot

	imageInfo.RawManifest = body

	if manifestReqType != registry.ManifestRequest_CosignSignature && !imageInfo.IsSignatureImage {
		signatureTag := GetCosignSignatureTagFromDigest(imageInfo.Digest)
		if signatureTag != "" {
			signatureImageInfo, _ := rc.GetImageInfo(ctx, name, signatureTag, registry.ManifestRequest_CosignSignature)
			// failed to get signature image info doesn't block vulnerability scan
			if signatureImageInfo == nil {
				signatureImageInfo = &ImageInfo{}
			}
			imageInfo.SignatureDigest = signatureImageInfo.Digest
		}
	}

	return imageInfo, share.ScanErrorCode_ScanErrNone
}

func (rc *RegClient) getSchemaV1Id(manV1 *manifestV1.SignedManifest) string {
	var id string
	if len(manV1.History) > 0 {
		v1com := manV1.History[0].V1Compatibility
		if i := strings.Index(v1com, "\"id\":\""); i >= 0 {
			v1com = v1com[i+6:]
			if i = strings.Index(v1com, "\""); i > 0 {
				id = v1com[:i]
			}
		}
	}
	return id
}

func (rc *RegClient) Alive() (uint, error) {
	return rc.Ping()
}

// GetCosignSignatureTagFromDigest takes an image digest and returns the default tag
// used by Cosign to store signature data for the given digest.
//
// # Example transition
//
// Given Image Digest: sha256:5e9473a466b637e566f32ede17c23d8b2fd7e575765a9ebd5169b9dbc8bb5d16
//
// Resulting Signature Tag: sha256-5e9473a466b637e566f32ede17c23d8b2fd7e575765a9ebd5169b9dbc8bb5d16.sig
func GetCosignSignatureTagFromDigest(digest string) string {
	signatureTag := []rune(digest)
	if i := strings.Index(digest, ":"); i > 0 {
		signatureTag[i] = '-'
		return string(signatureTag) + ".sig"
	} else {
		log.WithFields(log.Fields{"digest": digest}).Warn("unrecongnized image digest")
		return ""
	}
}
