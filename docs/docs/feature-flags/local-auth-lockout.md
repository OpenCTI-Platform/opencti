# Account lockout policy

!!! warning "Unreleased feature"

    This page documents the account lockout policy of the local authentication. It is only available when the `LOCAL_AUTH_LOCKOUT` feature flag is enabled (`APP__ENABLED_DEV_FEATURES='["LOCAL_AUTH_LOCKOUT"]'`), and this page is not published. When the flag is off, nothing is counted, nothing is locked and the settings are hidden.

    When the feature is released: move this page to `administration/local-auth-lockout.md`, add it to `nav` in `mkdocs.yml` after **Authentication**, and link it from:

    - `administration/authentication-via-ui.md`, at the end of **Local Authentication**: "To lock accounts after repeated failed login attempts, see [Account lockout policy](local-auth-lockout.md).";
    - `administration/users.md`, under **Account status**, after the **Locked** value: "The [account lockout policy](local-auth-lockout.md) can also set an account to Locked after repeated failed login attempts.".

The account lockout policy protects the local accounts against password guessing. When someone fails to log in too many times on the same account, the account is locked: for some minutes, or until an administrator unlocks it.

It only applies to the local authentication (email and password). Accounts that log in with SSO or LDAP are protected by their identity provider.

## Configure the policy

Go to **Settings > Security > Authentications**, open the **Local** strategy, and find **Account lockout policy**. You need two capabilities: **Manage authentication** to open this page, and **Manage credentials** to save the policy.

| Setting | Default | Allowed values |
|---|---|---|
| Lock accounts after repeated failed login attempts | Enabled on new platforms, disabled on upgraded platforms | On / Off |
| Maximum number of failed login attempts for users | `10` | 1 to 100 |
| Maximum number of failed login attempts for administrators | `3` | 1 to 100 |
| Action when the maximum number of failed login attempts is reached | Lock for the temporary lock duration | Temporary or permanent lock |
| Failed login attempts counter reset after (minutes) | `15` | 0 to 1440. `0` means no time limit |
| Temporary lock duration (minutes) | `15` | 1 to 1440. Only shown for the temporary lock |

The default values follow NIST SP 800-53 (control AC-7): 3 attempts for administrative accounts, 10 attempts for the other users, within 15 minutes.

**Administrative accounts** get the lower number of attempts. An account is administrative when it has one of these capabilities: **Bypass all capabilities**, **Manage credentials**, **Manage authentication** or **Access administration parameters**. All the other accounts, and the emails that match no account, get the number of attempts for users.

With an Enterprise Edition license, every change of these settings is recorded in the activity log.

## How it works

1. Each failed login on an account is counted. Nothing is locked before the maximum number of attempts.
2. The counter covers a window that starts with the first failure. When the window ends, the counter starts again from zero. With a window of `0`, the failures are kept until a successful login or an administrator.
3. When the maximum number of attempts is reached, the action applies:
    - **Temporary lock**: the account cannot log in for the temporary lock duration, then it is unlocked automatically. Its status stays **Active**, so its open sessions and API tokens keep working. A login attempt during the lock is rejected, even with the right password, and is not counted.
    - **Permanent lock**: the account status is set to **Locked**. Its open sessions are closed, and its API tokens stop working. The account stays locked until an administrator unlocks it.
4. A successful login resets the counter. For a user with two-factor authentication, only a valid code resets it: a right password alone does not.

### What is counted

- Failed passwords on the login form.
- Failed passwords with Basic authentication on the API.
- Failed two-factor authentication codes, at login and in the forgot password flow.

A login on an account that is inactive or expired is counted like a wrong password, without checking the password.

### What is not counted

- The built-in admin account (see [Built-in admin](#built-in-admin)).
- Attempts from an IP address that the IP whitelist blocks: they are rejected before being counted, so they cannot lock any account.
- Attempts on the login form while the local authentication is disabled.

### Accounts never set to Locked

Service accounts and the accounts of SSO and LDAP users are never set to **Locked** by the permanent lock. Their local login is still blocked after the maximum number of attempts. A successful login with their identity provider resets it.

### Unknown emails

An email that matches no account is counted too, with the same messages, so that a lock never reveals whether an account exists. Its failures and its lock are forgotten after one day.

## What users see

| Situation | Message |
|---|---|
| Failed login, before the maximum number of attempts | `Bad login or password` |
| Temporary lock | `Your account has been locked for security reasons. Please try again in 15 minutes.` (the remaining time, in minutes, then in hours from 60 minutes on) |
| Permanent lock | `Your account has been locked for security reasons. Please contact your administrator.` |

## Alerts for administrators

### Activity log

With an Enterprise Edition license, each lock is recorded in the activity log, with the `lock` scope. The event gives:

- the email of the account;
- the type of lock (temporary or permanent) and, for a temporary lock, its duration;
- the maximum number of attempts;
- where the last attempt came from: the login form, Basic authentication, a two-factor authentication code, or the forgot password flow;
- the IP address of the last attempt.

You can create an alert on these events to react fast. A lock on an email that matches no account is recorded too: many of them can show a credential stuffing attack.

### Email

When an existing account is locked, the administrators who can unlock it get an email:

- the active users with the **Manage credentials** capability (or **Bypass all capabilities**);
- with the organization segregation, the administrators of the organizations of the locked user.

The email gives the account, the number of failed attempts, the date of the lock and, for a temporary lock, its end date. Dates are in UTC. An SMTP server must be configured (see [SMTP configuration](../administration/smtp-configuration.md)).

The administrators get at most one email per account and per hour: an attacker can lock the same account again each time a temporary lock ends. Every lock is still recorded in the activity log. A successful login, or setting the account back to **Active**, ends this delay.

With an Enterprise Edition license, you can change the content of this email: edit the email template **Built-In Template For Locked Users** in **Settings > Security > Email templates**. It can use these variables:

- `$locked_user.name`, `$locked_user.firstname`, `$locked_user.lastname`, `$locked_user.user_email`: the locked account;
- `$lock.attempts`: the number of failed attempts;
- `$lock.date`: the date of the lock;
- `$lock.type`: `temporary` or `permanent`;
- `$lock.end_date`: the end of a temporary lock, empty for a permanent lock;
- `$lock.unlock`: a sentence that fits the lock: "The account is locked until <end date>." or "The account is locked until an administrator unlocks it.".

The `$user` variables are the administrator who gets the email.

The **Send test email** button of this template sends an example lock that follows the policy of the platform. If the template is deleted, the email is still sent with its default content, and the template is created again at the next start of the platform. Without an Enterprise Edition license, the email always uses its default content.

## Unlock an account

### Permanent lock

An administrator with the **Manage credentials** capability:

1. Goes to **Settings > Security > Users** and opens the locked user.
2. Clicks **Update**, and sets the **Account Status** back to **Active**.

The counter of the account is reset: the user can log in again, and has all the attempts again.

With the organization segregation, an administrator of an organization of the user can unlock it too.

### Temporary lock

A temporary lock ends on its own. To end it sooner, set the **Account Status** of the user to **Active** with the API (the account is already **Active**, so the form does not send it again):

```graphql
mutation {
  userEdit(id: "<user id>") {
    fieldPatch(input: { key: "account_status", value: ["Active"] }) { id }
  }
}
```

## Built-in admin

The built-in admin account is the one defined by `app:admin:email` and `app:admin:password` in the configuration. It is never locked: it is the account to use when every other administrator is locked.

Because it is never locked, its password can be guessed without limit. Once other administrators exist, disable it: set `APP__ADMIN__EXTERNALLY_MANAGED=true` (or `app:admin:externally_managed` in the configuration file) and restart the platform. The built-in admin account is then set to **Locked**.

Do not use the built-in admin token for connectors and workers: give each of them its own service account.

### If every administrator is locked

1. Set `APP__ADMIN__EXTERNALLY_MANAGED=false` in the configuration, with the admin email and password.
2. Restart the platform.
3. Log in with the built-in admin, and unlock the needed administrators:
    - a permanently locked administrator (status **Locked**): set it back to **Active** in its user form, see [Permanent lock](#permanent-lock);
    - a temporarily locked administrator (status still **Active**): the form cannot unlock it. Wait for the end of the lock, or end it with the API, see [Temporary lock](#temporary-lock).
4. Check that the unlocked administrators can log in, then set `APP__ADMIN__EXTERNALLY_MANAGED=true` again, and restart the platform.

## Recommendations

Anyone who knows the email of a user can lock their account on purpose. To limit this risk:

- Prefer SSO with multi-factor authentication for your users, and keep local accounts for a few emergency accounts.
- Disable the built-in admin after the setup.
- Restrict the network exposure of the platform: enable the IP whitelist, or put the platform behind a VPN. Attempts blocked by the IP whitelist never lock an account.
- With an Enterprise Edition license, monitor the `lock` events in the activity log, and create an alert on them.
- Give each connector and worker its own service account, never the token of an administrator: a lock of that administrator would stop them.
