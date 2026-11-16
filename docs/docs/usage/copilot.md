# Ask Ariane (AI chatbot)

**Ask Ariane** is the AI assistant built into OpenCTI. You open it from the top bar and ask it questions in natural
language, about the platform's knowledge or about the page you are looking at. This page explains what it needs, how to
use it, and what data it sends where.

!!! tip "Enterprise edition"

    Ask Ariane is available under the "OpenCTI Enterprise Edition" license.

    [Please read the dedicated page to have all information](../administration/enterprise.md)

## Why use it?

Ask Ariane saves you from building filters and dashboards for one-off questions. You can, for example:

- ask for the latest threats or recent reports on a topic,
- ask it to analyze the indicator or entity you have open,
- attach a document and ask questions about it,
- let it act on the platform for you, with your approval when the action is sensitive (see
  [Approving a tool call](#approving-a-tool-call)).

The assistant runs in [XTM One](https://docs.xtmone.io/), the Filigran AI platform. OpenCTI forwards your messages to it
and shows its answers. When it reads or changes data in OpenCTI, it does so with your own permissions, so it never shows
you more than you can already see.

## Prerequisites

### For administrators

1. **Enterprise Edition.** The platform needs a valid Enterprise Edition license, either an OpenCTI license or a
   Filigran license obtained through XTM One. See [Enterprise Edition](../administration/enterprise.md).
2. **Accept the Filigran AI Terms.** Go to **Settings > Filigran Experience**. In the AI row, click
   **Validate the Filigran AI Terms**, read the terms, tick the checkbox and click **I Agree to Filigran AI Terms**.
   The row is called **XTM One (Agentic AI)** when XTM One is configured, and **Agentic AI (Ariane Assistant)**
   otherwise. You need the **Manage parameters** capability, and the row only shows once Enterprise Edition is active.
3. **Connect XTM One.** Set `xtm:xtm_one_url` and `xtm:xtm_one_token` (environment variables `XTM__XTM_ONE_URL` and
   `XTM__XTM_ONE_TOKEN`). See [XTM Suite configuration](../deployment/configuration.md#xtm-suite).

Once the terms are accepted, the same row becomes a switch. Turning it off hides Ask Ariane for every user.

!!! note "Without an XTM One token"

    If no XTM One token is configured, Ask Ariane falls back to an earlier, simpler assistant hosted by Filigran
    (labelled **Preview** in **Settings > Filigran Experience**). It limits messages to 2,000 characters. To get the
    full experience described on this page, connect your platform to XTM One.

### For users

You need access to the knowledge of the platform (the **Access knowledge** capability). Users without it don't see the
button.

| What you see | Meaning |
|:-------------|:--------|
| No **Ask Ariane** button | An administrator turned the assistant off, or you don't have the **Access knowledge** capability. |
| The button shows an **EE** tag | The platform has no Enterprise Edition license. Clicking the button explains how to get one. |
| The tooltip says *Ask Ariane isn't activated yet* | The Filigran AI Terms have not been accepted yet. Ask an administrator to accept them. |

## Open the assistant

Click **Ask Ariane** in the top bar, at the right. The panel opens on the side of the page, and you can keep working
while it is open:

- drag its edge to resize it;
- it stays open, with the same width, when you navigate or reload the page.

Click the button again to close it.

## Ask a question

Type your question in the message box, or start from one of the suggestions, such as *What are the latest threats?*
or *Show me recent reports*. The answer appears as it is being written. You can send another message while it is still
writing, to refine your request.

### Questions about the current page

The assistant knows which page you are on: OpenCTI sends it the path of the page, which includes the identifier of the
entity you have open. So on the page of an indicator, *Analyze this indicator* is enough, without naming it.

Only the path is sent. Filters and search terms in the address bar are not.

### Links in answers

When an answer links to an entity or a page of the platform, clicking the link opens it in OpenCTI, without leaving the
conversation.

### Working in a draft

When you are working in a [draft](draftWorkspaces.md), the panel shows a colored border and the assistant works in that draft.
Anything it creates goes into the draft, not straight into the knowledge base.

## Attach files

You can attach files to a message, up to 50 MB per file, and ask questions about them. Files are sent to XTM One and
stored with the conversation.

When an answer produces a file, such as a report or a presentation, you can download it from the conversation.

## Conversation history

Conversations are saved in XTM One. You can start a new conversation, or reopen a previous one from the history.
Deleting a conversation removes it from your history.

You can rate an answer with a thumbs up or down. Your feedback is stored in XTM One, where the managers of the AI agent
can read it to improve it.

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

## CTEM Command Center

When the platform is connected to XTM One, a second button with a radar icon sits next to **Ask Ariane**. It opens the
CTEM Command Center of XTM One in a new browser tab. It does not require Enterprise Edition.

## Data and privacy

OpenCTI does not run the AI model itself. It forwards each request to XTM One, signed with a short-lived token that
identifies you (your user identifier and email address). The following data leaves the platform:

| Data | Sent to | Stored there |
|:-----|:--------|:-------------|
| Your messages and the path of the current page | XTM One | Yes, with the conversation |
| Files you attach | XTM One | Yes, with the conversation |
| Your ratings and comments on answers | XTM One | Yes |
| Your answers to approval prompts | XTM One | Yes, for **Yes, always** |

When the assistant needs data from OpenCTI, XTM One reads it through the API, with your permissions. Only what you are
allowed to see can reach an answer.

The platform's [usage telemetry](../reference/usage-telemetry.md) counts the number of messages sent to the assistant,
never their content.

## When something goes wrong

Errors appear in the conversation, in place of the answer.

| Message | What to do |
|:--------|:-----------|
| **Quota exceeded** | The AI usage quota of your organization is reached. Contact your administrator. |
| **XTM One is unreachable** | OpenCTI cannot reach XTM One. An administrator should check `xtm:xtm_one_url` and the network between the two. |
| **File exceeds maximum size limit** | The file is larger than 50 MB. |

## What's next?

- [Artificial intelligence in OpenCTI](../reference/artificial-intelligence.md): every AI feature of the platform.
- [Insights and summaries](insights.md): AI summaries on the page of an entity.
- [Ask AI](refine-content.md): AI help to write content and to search in natural language.
