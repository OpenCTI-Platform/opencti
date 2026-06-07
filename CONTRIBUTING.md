# Contributing to OpenCTI

Thank you for reading this documentation and considering making your contribution to the project. Any contribution that helps us improve the platform is valuable and much appreciated. If it is also meaningful to you or your organisation it’s all for the best.

In order to help you understand the project, where we are heading and how you can contribute, below are several resources and answers.

Do not hesitate to shoot us an [email](mailto:contact@filigran.io) or join us on our [Slack channel](https://community.filigran.io). Most of the articles below are an introduction for our [detailed documentation](https://docs.opencti.io/latest/).


## Why contribute?

OpenCTI is an open source project aiming at building a platform for threat intelligence analysts, allowing them to capitalise, structure, organise and visualise amounts of information. It allows analysts to leverage knowledge from this information while keeping track of each and every source of information (if you want to know more about OpenCTI, you can read the [detailed documentation](https://docs.opencti.io/latest/) or try it on the [demonstration platform](https://demo.opencti.io/)).

Whether you are an organisation or an individual working or studying in the field of cybersecurity and cyberdefense, or simply as an individual looking for a technical challenge, contributing to the OpenCTI project may represent a great opportunity for you.

* You can help grow the community and a tool focused on improving the understanding of cyberthreats and therefore enhancing our capability of better protecting our organisations and societies.

* You will be able to adapt the tool to your core interests and methods of work by developing features or fixing bugs you are most interested in.

* OpenCTI is also an interesting opportunity for developers to work on new technologies such as graph technologies.


## Where is the project heading?

Now that the first version of the tool has been released, our goal for the future releases is two-fold:

* Of course, fix bugs and develop features which are identified as non-critical but would really add up to OpenCTI's power.

* On a longer term vision, we would like to develop a multi-layered approach in the platform, which would be divided in three strata: a strategic level (for information about actors), a kill chain level (with the different steps of the attack chain) and an infrastructure level (containing data on the infrastructure used by the attacker).


## Code of Conduct

OpenCTI has adopted a Code of Conduct that we expect project participants to adhere to. Please read the [full text](https://github.com/OpenCTI-Platform/opencti/blob/master/CODE_OF_CONDUCT.md) so that you can understand which actions will and will not be tolerated.


## How can you contribute?

Any contribution is appreciated, and many don’t imply coding. Contributions can range from a suggestion for improving documentation, requesting a new feature, reporting a bug, to developing features or fixing bugs yourself.

For general suggestions or questions about the project or the documentation, you can open an issue on the repository with the label "question". We will answer as soon as possible. If you do not wish to publish on the repository, please see the section below [**"How can you get in touch for other questions?"**](#howcanyougetintouchforotherquestions).

* Just using OpenCTI and opening issues if everything is not working as expected will be a huge step forward. See our section about opening an issue. To report a bug, please refer to the [bug reporting module](https://github.com/OpenCTI-Platform/opencti/issues/new?assignees=&labels=&template=bug_report.md&title=). To suggest a new feature, please fill in the feature request [form](https://github.com/OpenCTI-Platform/opencti/issues/new?assignees=&labels=&template=feature_request.md&title=).

* Don’t hesitate to flag us an issue with the documentation or the templates if you find them incomplete or not clear enough. You can do that either by opening a [bug report](https://github.com/OpenCTI-Platform/opencti/issues/new?assignees=&labels=&template=bug_report.md&title=) or by sending us a message on our [Slack channel](https://community.filigran.io).

* You can look through opened issues and help triage them (ask for more information, suggest workarounds, suggest label, flag issues etc.)

* If you are interested in contributing to developing OpenCTI, please refer to the [detailed documentation](https://docs.opencti.io/latest/). It can be either to fix an issue which is meaningful to you, or to develop a feature requested by others.

### Pull requests focus

* All commit and Pull Request titles must follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification with a GitHub issue reference: `type(scope?)!?: description (#issue)` (for example `feat(backend): add bulk export endpoint (#1234)`). Allowed types are `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci` and `revert`. The old `[component]` bracket prefixes are **discontinued** — use a lowercase scope instead (e.g. `backend`, `frontend`, `client-python`, `worker`, `docs`, `ci`). The description starts with a lowercase letter and has no trailing period. See [`.github/LABELS.md`](.github/LABELS.md) for the full title & label taxonomy. **Renovate** pull requests are exempt.

* All commits must be signed. If you need to configure your git environment, please see the [GitHub documentation on signed commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

* All Pull Request must be linked to an issue and either fix a bug, implement a feature or improve documentation.

* Documentation should be inside the Pull Request in the `docs` folder.

* As much as possible, provide advices on how to test the feature or the bug fix you implemented in the Pull Request.

### How can you get in touch for other questions?

If you need support or you wish to engage a discussion about the OpenCTI platform, feel free to join us on our [Slack channel](https://community.filigran.io). You can also send us an [email](mailto:contact@filigran.io).
