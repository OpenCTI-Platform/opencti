# Support Package

Support packages are useful for troubleshooting issue that occurs on OpenCTI platform.
Administrators can request to create and download a support package that contains recent platform error logs and usage statistics.

Support Package can be requested from "Settings > Support" menu.

![Support package overview](./assets/support-package-overview.png)

## Package generation

On a click on "Generate support package", a support event is propagated to every platform instances to request needed information.
Every instance that will receive this message will process the request and send the files to the platform.
During this processing the interface will display the expected support package name in an IN PROGRESS state waiting for completion.
After finishing the process the support package will move to the READY state and the buttons download and delete will be activated.

## Package download

After file generation, using the download button will dynamically create a (zip) containing all instances logs and telemetry.

## Partial package

In case of platform instability, some logs might not be retrieved and the support package will be incomplete.

If some instances fail to send their data, you will be able to force download a partial zip only after 1 minute. In case of a support package taking more than 5 minutes, the status will be moved to "timeout".
