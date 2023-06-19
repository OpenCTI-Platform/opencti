# Introduction

This guide aims to give you a full overview of the OpenCTI features and workflows. The platform can be used in various contexts to handle threats management use cases from a technical to a more strategic level.

# Administrative Settings
The OpenCTI Administrative settings console allows administrators to configure many options dynamically within the system. As an Administrator, you can access this settings console, by clicking the settings link.
![Settings Link](./assets/system_settings.png?raw=true "System Settings")

The Settings Console allows for configuration of various aspects of the system.
## General Configuration
  - Platform Title (Default: OpenCTI - Cyber Threat Intelligence Platform)
  - Platform Favicon
  - Platform General Sender email (Default: admin@opencti.io) 
  - Platform Default Theme (Default: Dark)
  - Language (Default: Automatic Detection)
  - Hidden Entity Types (Default: None)

## Authentication Strategies Display
  - This section will show configured and enabled/disabled strategies. The configuration is done in the config/default.json file or via ENV variables detected at launch.

## Platform Messages
  - Platform Login Message (optional) - if configured this will be displayed on the login page. This is usually used to have a welcome type message for users before login.
  - Platform Consent Message (optional) - if configured this will be displayed on the login page. This is usually used to display some type of consent message for users to agree to before login. If enabled, a user must check the checkbox displayed to allow login.
  - Platform Consent Confirm Text (optional) - This is displayed next to the platform consent checkbox, if Platform Consent Message is configured. Users must agree to the checkbox before the login prompt will be displayed. This message can be configured, but by default reads: ***I have read and comply with the above statement***

![Platform Messages](./assets/platform_message_examples.png?raw=true "Platform Messages")

## Dark Theme Color Scheme
Various aspects of the Dark Theme can be dynamically configured in this section.

## Light Theme Color Scheme
Various aspects of the Light Theme can be dynamically configured in this section.
## Tools Configuration Display
This section will give general status on the various tools and enabled components of the currently configured OpenCTI deployment.
