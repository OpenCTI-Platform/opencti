# Policies

The Policies configuration window (in "Settings > Security > Policies") encompasses essential settings that govern the organizational sharing, authentication strategies, password policies, login messages, and banner appearance within the OpenCTI platform.


## Platform main organization

Allow to set a main organization for the entire platform. Users belonging to the main organization enjoy unrestricted access to all data stored in the platform. In contrast, users affiliated with other organizations will only have visibility into data explicitly shared with them.

![Platform main organization](./assets/platform-main-organization.png)


!!! warning "Numerous repercussions linked to the activation of this feature"

    This feature has implications for the entire platform and must be fully understood before being used. For example, it's mandatory to have organizations set up for each user, otherwise they won't be able to log in. It is also advisable to include connector's users in the platform main organization to avoid import problems.

## Authentication strategies

The authentication strategies section provides insights into the configured authentication methods. Additionally, an "Enforce Two-Factor Authentication" button is available, allowing administrators to mandate 2FA activation for users, enhancing overall account security.

Please see the [Authentication section](../deployment/authentication.md) for further details on available authentication strategies.

![Authentication strategies](./assets/authentication-strategies.png)


## Local password policies

This section encompasses a comprehensive set of parameters defining the local password policy. Administrators can specify requirements such as minimum/maximum number of characters, symbols, digits, and more to ensure robust password security across the platform. Here are all the parameters available:

| Parameter                                                               | Description                                                   |
|:------------------------------------------------------------------------|:--------------------------------------------------------------|
| `Number of chars must be greater than or equals to`                     | Define the minimum length required for passwords.             |
| `Number of chars must be lower or equals to (0 equals no maximum)`      | Set an upper limit for password length.                       |
| `Number of symbols must be greater or equals to`                        | Specify the minimum number of symbols required in a password. |
| `Number of digits must be greater or equals to`                         | Set the minimum number of numeric characters in a password.   |
| `Number of words (split on hyphen, space) must be greater or equals to` | Enforce a minimum count of words in a password.               |
| `Number of lowercase chars must be greater or equals to`                | Specify the minimum number of lowercase characters.           |
| `Number of uppercase chars must be greater or equals to`                | Specify the minimum number of uppercase characters.           |
| `Password validity duration in days (0 equals unlimited)`              | Define how long a password remains valid before the user is forced to change it. A value of `0` means passwords never expire. |
| `Number of recent passwords that cannot be reused (0 equals disabled)` | Refuse a new password equal to the current one or to one of the previous ones, from `0` to `24`. See [Password history](#password-history). |

![Local password policies](./assets/local-password-policies.png)


## Password validity and forced password change

When a non-zero password validity duration is configured, each user's password is assigned an expiration date (visible in the user overview and user list as "Password valid until"). Once expired, the user is redirected to a dedicated password change screen upon their next interaction with the platform.

### How it works

1. **Admin configures the policy**: In "Settings > Security > Policies > Local password policies", set the "Password validity duration in days" to a non-zero value (e.g., 90).
2. **Expiration is computed**: When a user sets or changes their password, the expiration date is set to `now + N days`.
3. **Enforcement**: Once the date is reached, the user cannot perform any action until they set a new password.
4. **Admin-triggered reset**: Administrators can also force a password change for specific users (individually or in bulk) via the user management interface.

### Admin actions

- **Individual reset**: In the user edition drawer (Password tab), click "Force password change". This immediately sets the user's `password expiration date` to the current time, forcing a change on their next request.
- **Bulk reset (Mass operation)**: In the users list, select the target users, click **Mass operation**, then set **Password valid until** to **Today** and apply. This expires all selected users' passwords immediately and forces a password change on their next request.
 - **Policy change**: When the validity duration is changed, existing users' password expiration dates may be recalculated to align with the new policy. Setting the value back to `0` disables password expiration.

### User experience

- **Authenticated users**: When a password expires while the user is logged in, they are redirected to a dedicated full-screen password change page.
- **At login**: If the password is already expired at login time, the user is shown a password change form directly within the login page.
- **Session invalidation**: After changing an expired password, all other active sessions for that user are terminated.

## Password history

!!! note "Feature in development"

    Password history is behind the `PASSWORD_HISTORY` development feature flag. The setting only appears, and is only enforced, when the flag is enabled.

Password history prevents users from going back to a password they used recently. It applies to local accounts only: accounts authenticated by an external provider (SSO, LDAP, etc.) and service accounts are not concerned.

### How it works

1. **Admin configures the policy**: In "Settings > Security > Policies > Local password policies", set "Number of recent passwords that cannot be reused" to a value between `1` and `24`.
2. **The count includes the current password**: with `1`, a new password only has to differ from the current one. With `5`, it must differ from the current password and the 4 before it.
3. **Every password change is checked**: when users change their own password (profile, forced change, forgot password) and when an administrator sets a password for a user.
4. **Only hashes are kept**: the platform stores the hashes of the previous passwords, never the passwords themselves. Comparison is an exact match: a slightly different password (`Summer2025!` instead of `Summer2024!`) is accepted.

The history starts from the moment the rule is enabled: passwords set before that are not known to the platform. Lowering the value drops the oldest passwords beyond the new count. Setting it back to `0` disables the rule and deletes every user's password history, so enabling it again starts from scratch.

!!! warning "Long passwords"

    Passwords are compared on their first 72 bytes, a limit of the bcrypt hashing algorithm. Two passwords that share their first 72 bytes are considered identical.

### User experience

- The password rules shown next to the password fields include "Must be different from your last N passwords" (or "your current password" when the value is `1`). This rule cannot be checked while typing, since only the platform knows the previous passwords.
- A refused password shows: "This password has already been used recently. Please choose a different one." In the forgot password flow, the user stays on the new password step and can try again with the same code.
- To limit guessing, a user can submit at most 5 password changes per 15 minutes, counted once the new password meets the other policies. Beyond that, the change is refused with "Too many password change attempts. Please try again in a few minutes." Both values can be changed with `app:password_change:max_attempts` and `app:password_change:window_seconds` (see [Configuration](../deployment/configuration.md#network-and-security)).

### Audit and alerting

Each refused reuse is recorded in the audit log as an unauthorized action (`password_reuse`), with the target user and the flow (`self`, `admin` or `reset`), and never with the password itself. The platform also writes a warning line in its application log. With an Enterprise Edition license, you can build alerts on these activity events.

### Backups and API

Password hashes, current and previous, live in the user documents of Elasticsearch / OpenSearch: protect backups of the database accordingly. The history cannot be read or written through the API, and a password change must be sent on its own, without any other field in the same request.

## Login messages

Allow to define messages on the login page to customize and highlight your platform's security policy. Three distinct messages can be customized:

- Platform login message: Appears above the login form to convey important information or announcements.
- Platform consent message: A consent message that obscures the login form until users check the approval box, ensuring informed user consent.
- Platform consent confirm text: A message accompanying the consent box, providing clarity on the consent confirmation process.

![Login message configuration](./assets/login-message-configuration1.png)
![Login message configuration](./assets/login-message-configuration2.jpeg)

![Login message illustration](./assets/login-message-illustration1.jpeg)
![Login message illustration](./assets/login-message-illustration2.png)


### Platform banner configuration

The platform banner configuration section allows administrators to display a custom banner message at the top and bottom of the screen. This feature enables customization for enhanced visual communication and branding within the OpenCTI platform. It can be used to add a disclaimer or system purpose.

This configuration has two parameters:

- Platform banner level: Options defining the banner background color (Green, Red, or Yellow).
- Platform banner text: Field referencing the message to be displayed within the banner.

![Platform Banner](./assets/platform_banner.png)
