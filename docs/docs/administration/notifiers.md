# Custom notifiers

Leveraging the platform's built-in connectors, users can create custom notifiers tailored to their unique needs, under Platform > Customization > Notifiers.
OpenCTI features three built-in connectors:

- a webhook connector,
- a simple mailer connector,
- and a platform mailer connector.

These connectors operate based on registered schemas that describe their interaction methods.

![Notifier connectors](assets/notifier-connectors.png)


### Built-In notifier connectors

#### Platform mailer

This notifier connector enables customization of notifications raised within the platform. It's simple to configure, requiring only:

- Title: The title for the platform notification.
- Template: Specifies the message template for the notification.

![Platform email notifier](assets/platform-email-notifier.png)

In the message template, you can insert attributes of the concerned data.
For instance, for the entity name, use: `<%=data[0].instance.name%>`

You can use the `octi.markdownToHtml` function to convert markdown data to html data.
For instance, to display properly the entity description, use: `<%-octi.markdownToHtml(data[0].instance.description)%>`;


#### Simple mailer

This notifier connector offers a straightforward approach to email notifications with simplified configuration options. Users can set:

- Title: The title for the email notification.
- Header: Additional content to include at the beginning of the email.
- Footer: Additional content to include at the end of the email.
- Logo: The option to add a logo to the email.
- Background Color: Customize the background color of the email.

![Custom email notifier](assets/custom-email-notifier.png)

#### Webhook

This notifier connector enables users to send notifications to external applications or services through HTTP requests. Users can specify:

- Verb: Specifies the HTTP method (GET, POST, PUT, DELETE).
- URL: Defines the destination URL for the webhook.
- Template: Specifies the message template for the notification.
- Parameters and Headers: Customizable parameters and headers sent through the webhook request.

OpenCTI provides two notifier samples by default, designed to communicate with Microsoft Teams through a webhook. A [documentation page](notifier-samples.md) providing details on these samples is available.


### Configuration and access

Custom notifiers are manageable in the "Settings > Customization > Notifiers" window and can be restricted through Role-Based Access Control (RBAC). Administrators can control access, limiting usage to specific Users, Groups, or Organizations.

For guidance on configuring notification triggers and exploring the usages of notifiers, refer to the [dedicated documentation page](../usage/notifications.md).

For security reason, the authorized methods that can be used in webhook template is limited, see [notifier_authorized_functions parameter](https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/config/default.json).
If you need to extend this authorization, you can update `APP__NOTIFIER_AUTHORIZED_FUNCTIONS` with a custom list. The default managed list by OpenCTI is safe, please be aware that you extends this list at your own risk.