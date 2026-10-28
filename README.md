# Reviewed CSI images

Build recipes for the NFS CSI driver, node registrar and liveness probe.
Upstream source archives, Go modules, toolchains, runtime packages and the scanner
are locked by immutable revision and SHA-256. Upstream license files are retained
inside the built images. Sidecars use a scratch runtime. The NFS runtime uses
Debian 13 and includes its mount helper. Only Linux/amd64 is selected.

`images/image-policy.json` is a generated consumer excerpt of the exact APP
contract named in `images/build-lock.json`. It is not an independent policy.
The full private contract is not included. The native consumer independently
checks the projection against the pinned full source before admitting images.
No vulnerability is suppressed. Passing a scan does not prove a native mount.

Publication runs only by manual dispatch from protected main, with source_sha
matching the current commit and koad7 as actor and triggering actor. All three
upstream test/build/scan jobs must pass before the protected environment permits
publication. The publisher emits hosted SLSA provenance, SPDX and Trivy scan
attestations for every exact image digest. Existing source tags cannot be
replaced. A failed attestation leaves the pushed image unadmitted.

The repository and these three image packages are proposed public:

- ghcr.io/crewsbridge/csi-images/csi-nfs
- ghcr.io/crewsbridge/csi-images/csi-registrar
- ghcr.io/crewsbridge/csi-images/csi-liveness

Source/build logs, dependency inventories, binaries, remaining vulnerabilities,
attestations, and the policy source repository name/commit/path/hash are public.
Application source, deployment manifests, infrastructure identities and secrets
are not included. No cloud, cluster or application credentials enter a workflow.

Required configuration: protect main with no bypass/force-push/deletion,
require the source-checks result and a pull request, and protect environment
csi-image-publication with reviewer koad7 and an exact main deployment branch
rule. Self-review stays allowed because no second owner is authorized.
Administrator environment bypass is disabled. Default token permission is read.
Public standard hosted runners only; no paid larger runners or spending changes.

Consumers must verify all three attestation predicate types against exact source,
signer workflow, signer commit, main ref, hosted builder and subject digest.
They also compare the verified scan image identity with the registry image's
Linux/amd64 config digest and enforce their independently pinned current policy.
Public package visibility and anonymous digest pulls are checked separately.
Publication does not authorize native installation or production activation.
