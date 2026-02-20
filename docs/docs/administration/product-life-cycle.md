# Product Life Cycle 

This page defines OpenCTI’s product life cycle, including version numbering, Long-Term Support (LTS) program, dependency management, and breaking change policies. 

Understanding these policies will help you plan deployments, manage upgrades, and maintain a stable OpenCTI environment.

## Version Numbering Scheme

OpenCTI has adopted a date-based versioning scheme that reflects our continuous delivery model. Releases are published when ready, ensuring that critical fixes and improvements reach users without unnecessary delays.


### Version Format

| Version Format       | Description          |
|:---------------------|:---------------------|
| `x.dddddd.z`         | Non-LTS version <br> `x` = major version number <br> `dddddd` = release date (YYMMDD) <br> `z` = sequential number for same-day releases (including LTS releases)|
| `x.dddddd.z-lts(.n)` | LTS version <br> `x` = major version number <br> `dddddd` = LTS branching date (YYMMDD) <br> `z` = sequential number for same-day releases (including non-LTS releases) <br> `n` = sequential hotfix number (starts at 1)|

### Version Examples

**Non-LTS versions:**

- **7.260112.0** — Release from January 12, 2026, major version 7
- **7.260112.1** — Second release on the same day
- **7.260315.0** — Release from March 15, 2026, major version 7

**LTS versions:**

- **7.260201.0-lts** — LTS branched February 1, 2026, released March 1, 2026
- **7.260201.0-lts.1** — First hotfix for the 7.260201-lts release
- **7.260201.0-lts.2** — Second hotfix for the 7.260201-lts release

!!! info "Note on Major Version Numbers"

    The major version number `x` is used to indicate important evolutions within the product that might imply breaking changes or major architectural shifts.

### Release Frequency

Non-LTS releases are delivered when ready, which can range from daily to weekly depending on the urgency of fixes, new features, and quality assurance requirements. This flexible approach ensures:

- Critical security fixes reach users as quickly as possible
- Bug fixes are not artificially delayed by release schedules
- New features become available to users continuously

## Long-Term Support (LTS) Program

The LTS program provides a stable, predictable release path for organizations that require rigorous testing, validation, and deployment processes. LTS releases evolve slowly and receive only critical & security fixes, ensuring minimal disruption to production environments.


### Why LTS ?

Many organizations operate within strict internal processes for testing, validation, deployment, and maintenance. These cycles can be lengthy, making it impossible to upgrade to every new version of OpenCTI. The LTS program addresses these challenges by providing:

- **A stable release line** that evolves more slowly
- **Updates limited to critical fixes** (major bugs and security fixes only)
- **A clear time window** during which the release remains supported
- **Predictable upgrade cadence** aligned with operational constraints

!!! warning "Important"

    LTS is not a mandatory path. It is an option for organizations that prefer stability over rapid adoption of new features. Organizations comfortable with frequent updates may continue using non-LTS releases to access the latest capabilities. 

!!! warning "Important"

    LTS is only available for On-Prem customers. LTS is not available for SaaS customers, as Filigran is handling deployment and maintenance. 

### LTS Program Characteristics ?

**Release Cadence:**

- LTS releases occur every **6 months**
- Each LTS version is supported for **1 year** from its release date
- This provides a **6-month overlap window** to prepare and test migration to the next LTS

**Stabilization Period:**

- Each LTS release is stabilized for **1 month** before being published
- This ensures reliability and reduces post-release issues

**Update Policy:**

- LTS updates are **limited to critical bug fixes or security fixes**
- No new features are added to LTS versions
- Hotfixes are released on an as-needed basis

**What qualifies as a critical or major bug?**

A bug is considered critical if it renders a feature unusable from a user standpoint. This includes:

- Complete failure of a core feature or workflow
- Data loss or corruption issues
- Significant performance degradation that blocks normal operations
- Regressions

### LTS Release Timeline Example

The following timeline illustrates how an LTS release progresses from branching through end of life:

| Date                 | Event                                      |
|:---------------------|:-------------------------------------------|
| Feb 1, 2026.         | 7.260201.0-lts branched from latest release|
| Feb 1 - Mar 1        | 1-month stabilization period               |
| Mar 1, 2026          | 7.260201.0-lts officially released         |
| Aug 1, 2026          | Next LTS (7.260801.0-lts) branched         |
| Sep 1, 2026          | 7.260801.0-lts released (6-month overlap begins)         |
| Mar 1, 2027          | 7.260201.0-lts reaches End of Life (EOL)         |

!!! tip "Key Insight: Overlap Window"

    The 6-month overlap between consecutive LTS releases (September 2026 to March 2027 in this example) gives organizations ample time to validate the new LTS version while the previous version remains fully supported.

### Choosing Between LTS and Non-LTS Release

Selecting the right release path depends on your organization’s operational model, risk tolerance, and resource availability.

#### When to Use LTS

LTS is recommended if your organization:

- Requires extensive internal testing and validation before deploying updates
- Operates in regulated industries with strict change management processes
- Prefers predictable, infrequent upgrades over continuous updates
- Values minimal functional changes in production environments
- Has limited resources to manage frequent version updates

#### When to Use Non-LTS

Non-LTS releases are recommended if your organization:

- Values access to the latest features and improvements
- Can deploy and test updates frequently
- Prefers receiving bug fixes and enhancements as soon as they’re available
- Has a flexible change management process
- Operates in a development or testing environment

### How to Access LTS Releases

LTS releases are distributed as protected container images. Everyone can run such images but you need a specific LTS license key to effectively use OpenCTI.

To activate LTS for your organization:

1. Contact your Account Executive or Customer Success Manager
2. Request an LTS license for your deployment
3. Receive your license key and deployment instructions
4. Configure your deployment with the provided license key

## Deprecation & Breaking change Policy

!!! info "" 

    As long as the code is doing no harm, we only deprecate. Breaking change only occurs if the code is problematic for technical, business or legal reasons.

A breaking change is any modification that causes:

- Existing features to become non-functional or behave differently
- API integrations to fail or return different results
- Configuration files to become invalid or incompatible
- Data models to change in ways that require a manual migration
- Workflows or automations to stop executing as expected


## External dependencies

OpenCTI relies on various external dependencies including databases, message queues, programming language runtimes, and third-party libraries. This section outlines how we manage the lifecycle of these dependencies to ensure stability, security, and compatibility across all release types.


### Dependency Management Principles

OpenCTI enforces strict dependency management practices to ensure consistency and reliability:

**Fixed Versioning**

- All dependencies use fixed version numbers in configuration files
- No semantic versioning syntax like `2.5.x` or `~2.5.4` — only explicit versions such as `2.5.7`
- Lock files are committed to the repository and shared across all installations
- This ensures everyone using the same version of OpenCTI has the same fixed set of packages

**Automated Monitoring**

- Automated tooling (Renovate bot) continuously monitors dependency releases
- Pull requests are automatically generated when new versions become available
- Security scanning tools (Dependabot, Snyk) identify vulnerable dependencies
- The development team reviews and merges updates regularly

### Deprecation Timeline and Communication

When dependencies, feature or API endpoints are deprecated (or reach end-of-life), Filigran follows a structured communication and migration process:

**Advance Notice Period**

- Deprecation notices are provided **at least 6 months** before a dependency is removed
- For LTS versions, notices align with the LTS support windows to avoid mid-cycle disruptions

**Communication Channels**

- Release notes for affected versions
- Updated technical documentation with migration guidance
- Direct notifications to LTS customers via Customer Success Managers

**Migration Support**

- Comprehensive migration guides documenting all required changes
- Code examples and configuration updates where applicable
- Testing guidelines to validate compatibility before production deployment
- Technical support for customers with complex deployment scenarios

## Connector Compatibility

OpenCTI connectors are essential integrations that enable data exchange with external systems. Connector compatibility follows specific rules to ensure stable and reliable operations.

### LTS Connector Compatibility

For connectors managed by XTM Composer:

- Each connector version is **aligned with and tied to its corresponding LTS version**
- Connector updates for LTS releases include only critical fixes, mirroring the LTS philosophy

For manually managed connectors:

- **Only connectors with versions matching the LTS version are officially supported**
- Using mismatched connector versions may result in compatibility issues or unsupported configurations


!!! tip "Best Practice"

    Always ensure your connectors are updated to match your OpenCTI LTS version. Check connector version compatibility before upgrading your OpenCTI platform.


### Breaking Changes and Connector API

!!! tip "Under construction"

    This section is under construction


## Additional Information

### LTS Upgrade Paths

!!! tip "Under construction"

    This section is under construction

### SaaS Deployments

OpenCTI SaaS customers do not use the LTS program. The primary benefit of SaaS is managed updates and access to the latest version of OpenCTI at all times. SaaS deployments automatically receive:

- Critical bug fixes and Security fixes as soon as they are available
- New features and improvements continuously
