---
applyTo: "**/*"
description: "Code review checklist: security vulnerabilities, performance issues, code quality, and readability improvements"
---

When reviewing code, focus on:

## Security Critical Issues
- Check for hardcoded secrets, API keys, or credentials
- Look for SQL injection and XSS vulnerabilities
- Verify proper input validation and sanitization
- Review authentication and authorization logic

## Performance Red Flags
- Identify N+1 database query problems
- Spot inefficient loops and algorithmic issues
- Check for memory leaks and resource cleanup
- Review caching opportunities for expensive operations

## Code Quality Essentials
- Functions should be focused and appropriately sized
- Use clear, descriptive naming conventions
- Ensure proper error handling throughout

## Log Severity
Flag any logging call whose level does not match what actually happened. The rule
is the pager test: `logApp.error` is for a failure **someone can act on** — work
lost, or a platform function down. If the code skips one item and continues, takes
a fallback, schedules a retry, or reports a remote/user-configured failure, it is
`logApp.warn`. A message containing "skipping", "retrying" or "unsupported" at
`error` level is almost always wrong. Full rules and the recurring patterns:
[Logging Levels](backend/patterns/logging-levels.md).

Comment with the level you'd expect and the reason, not just the rule — for example:
"This skips one element and the loop continues, so `warn` fits better than `error`;
consider an aggregate count after the loop." Only raise it when the current level is
clearly wrong; a defensible judgement call is not worth a comment.

Also flag, on any logging line: intelligence content in the metadata (STIX bundles,
observable values, indicator patterns, resolved connector configs), and an exception
passed as `{ error: e.message }` rather than `{ cause: e }`, which discards the stack.

## Feature Flags
When a change introduces or uses a feature flag (`*_FEATURE_FLAG`, `@ff`,
`enforceEnableFeatureFlag`, `isFeatureEnabled`), check that every new attribute definition
and every new nested `mappings` entry of the feature sets `featureFlag: <FLAG_CONSTANT>`.
A missing one silently adds the field to the ElasticSearch mapping with the flag off.
See [Feature Flags](backend/patterns/feature-flags.md).

## Review Style
- Be specific and actionable in feedback
- Explain the "why" behind recommendations
- Acknowledge good patterns when you see them
- Ask clarifying questions when code intent is unclear

Always prioritize security vulnerabilities and performance issues that could impact users.

Always suggest changes to improve readability. For example, this suggestion seeks to make the code more readable and also makes the validation logic reusable and testable.

// Instead of:
if (user.email && user.email.includes('@') && user.email.length > 5) {
  submitButton.enabled = true;
} else {
  submitButton.enabled = false;
}

// Consider:
function isValidEmail(email) {
  return email && email.includes('@') && email.length > 5;
}

submitButton.enabled = isValidEmail(user.email);
