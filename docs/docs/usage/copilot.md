# Interactions using AI (chatbot)

!!! tip "Under construction"

    This page is under construction

## Approving a tool call

The assistant can call tools to act on the platform. Some tools are gated: when the assistant
proposes one, the answer stops and the panel asks you to decide. The prompt names the tool and
the arguments it would use, and nothing runs until you answer.

| Answer | Effect |
|:----------------|:-------------------------------------------------------------------------|
| **Approve**     | Runs once. The next call asks again.                                     |
| **Decline**     | Does not run. Add a reason and the assistant can adapt to it.            |
| **Yes, always** | Runs, and saves a preference so this tool stops asking you.              |

!!! warning "Always-allow also covers runs nobody is watching"

    The preference saved by **Yes, always** applies beyond this conversation, including scheduled
    runs with no one present to review them, until you revoke it. Use **Approve** for anything you
    mean to allow only once.

Reloading the page keeps a displayed prompt: the assistant is still waiting, and the turn resumes
once you answer.

Which tools are gated is configured in XTM One, not in OpenCTI. If nothing is gated, you never see
this prompt. Features with no one in front of them — AI Insights, or an AI agent component in a
playbook — cannot show it, so they stop instead of acting and report that approval was required.
