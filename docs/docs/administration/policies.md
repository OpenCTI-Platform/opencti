# Policies

## Platform main organization

Allow to set a main organization for the entire platform.

All the pieces of knowledge must be shared with the organization of the user wishing to access it or this user need to
be inside the main organization.

## Authentication Strategies

There are several authentication strategies to connect to the platform.

Please see the [Authentication section](../deployment/authentication.md) for further details.

## Local Password Policies

Allow to define the password policy according to several criteria in order to strengthen the security of your platform,
namely: minimum/maximum number of characters, number of digits, etc.

## Login Messages

Allow to define login, consent and consent confirm message to customize and highlight your platform's security policy

## Platform Banner Configuration

Allow OpenCTI deployments to have a custom banner message (top and bottom) and colored background
for the message (Green, Red, or Yellow). Can be used to add a disclaimer or system purpose that will be displayed
at the top and bottom of the OpenCTI instances pages.

This configuration has two parameters:

- Platform Banner Level - (Default: OFF) Options available for the banner background are Green, Red, and Yellow.
- Platform Banner Text - (Default: Blank) If you turn on the banners, you should add a message to this area to be
  displayed within the banner.

![Platform Banner](./assets/platform_banner.png?raw=true "Platform Banner")
