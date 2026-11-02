# Security Policy

## Reporting a Vulnerability

Report suspected vulnerabilities privately to [manuel@christlieb.eu](mailto:manuel@christlieb.eu).
Please include the affected package version, a description of the impact, and reproduction
steps or a minimal proof of concept. Remove credentials, signing keys, tokens, and personal
data from reports. Do not open a public issue or pull request containing vulnerability details
before a fix and disclosure have been coordinated.

## Supported Versions

Before the first tagged release, security fixes target `main`. After release, only the latest
published release receives security fixes. Reports about any version are welcome; include
whether the issue also affects the latest release if you can verify it. Older releases do not
receive backported fixes.

The minimum supported Rust version is 1.88.

## Compatibility Before 1.0

During `0.x`, minor releases may include breaking changes. Patch releases are intended to
preserve compatibility; a security fix may require a breaking change, which will be identified
in the release notes. Review release notes and test your integration before upgrading.
