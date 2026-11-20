// Built-in template of the email sent to the administrators when the local authentication lockout locks an account.
// $user is the recipient (an administrator), $locked_user the locked account and $lock the lock itself
const LOCKED_USER_EMAIL_TEMPLATE_BODY = `<p>
  <span>Dear $user.firstname $user.lastname,</span>
</p>
<p>
  <span>The account of <strong>$locked_user.name</strong> ($locked_user.user_email) has been locked on $lock.date, after $lock.attempts failed authentication attempts.</span>
</p>
<p>
  <span>$lock.unlock</span>
</p>
<p>
  <span>If this user did not make these attempts, the account may be the target of an attack: check the activity of the platform.</span>
</p>
<ul>
  <li>
    <span>Platform url: $settings.platform_url</span>
  </li>
</ul>`;

export const LOCKED_USER_EMAIL_TEMPLATE_INPUT = {
  name: 'Built-In Template For Locked Users',
  description: 'Default email template to notify the administrators when an account is locked after failed authentication attempts',
  email_object: 'OpenCTI account locked',
  sender_email: 'OpenCTI Administrator',
  template_body: LOCKED_USER_EMAIL_TEMPLATE_BODY,
};
