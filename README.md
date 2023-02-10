### Attach SBOM

Simple CLI tool to attach SBOM to OCI artifacts according to OCI v1.1 spec and [Cosign SBOM spec](https://github.com/sigstore/cosign/blob/main/specs/SBOM_SPEC.md). 

### Usage

```bash
./attach-sbom <image> <sbom-dir>
```
NOTE: only works with TTL as registry auth isn't there. 


### Output
``` bash
crane manifest <image with attached SBOM>
```

```
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.dev.cosign.artifact.sbom.v1+json",
    "size": 669,
    "digest": "sha256:b5af1565ca06a6163b8712cbfa653a712774280856639bc1eee5a1ca7ba99b7d"
  },
  "layers": [
    {
      "mediaType": "application/vnd.syft+json",
      "size": 621,
      "digest": "sha256:4b6da9488c8c58b0cf2a6ab17ec6c1f61c253c72fae89058e0f36a9d2b56ff38"
    },
    {
      "mediaType": "text/spdx+json",
      "size": 3154,
      "digest": "sha256:ccd7ff261d5506b9345c0b066b903bd0ef2d8ccd9f833ce738773d19c57f517e"
    },
    {
      "mediaType": "application/vnd.cyclonedx+json",
      "size": 2906,
      "digest": "sha256:ebb95fb9dcfb1b3d3d664808382288418b9a306fc72162ab7927ab1c2391a705"
    },
    {
      "mediaType": "text/spdx+json",
      "size": 3154,
      "digest": "sha256:ccd7ff261d5506b9345c0b066b903bd0ef2d8ccd9f833ce738773d19c57f517e"
    },
    {
      "mediaType": "application/vnd.syft+json",
      "size": 1908,
      "digest": "sha256:329ad9279e22c942e68e53ef5e057d3c9ad8812f871ef872c1deb525d985176f"
    }
  ],
  "subject": {
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "size": 2528,
    "digest": "sha256:b4494e4f7efd07380908d4a74c6d85aa4151bf497bdf32d40d3229fe7ebdee24"
  }
}
```

crane blob can now be used to download the SBOM. 