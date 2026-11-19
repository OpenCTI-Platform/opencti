import { on } from 'mokapi'

const AGENT_CALL_DELAY_SECONDS = 120

const CHATBOT_ANSWER = 'You are using the XTM One mock (Mokapi): no AI agent answers here.'

const sseFrame = (data) => `data: ${JSON.stringify(data)}\n\n`

export default function () {
  on('http', async (request, response) => {
    if (request.key === '/api/v1/platform/chat/quota') {
      response.body = 'null'
      return
    }
    if (request.key === '/api/v1/platform/chat/conversations/{conversationId}/pending-approvals') {
      response.data = { conversation_id: request.path.conversationId, proposals: [], turn: 'idle' }
      return
    }
    if (request.key !== '/api/v1/platform/chat/messages') {
      return
    }
    if (request.body?.stream) {
      response.headers['Content-Type'] = 'text/event-stream'
      response.body = sseFrame({ type: 'stream', content: CHATBOT_ANSWER })
        + sseFrame({ type: 'done', content: CHATBOT_ANSWER, conversation_id: '00000000-0000-4000-8000-000000000001' })
      return
    }
    if (request.url.path.startsWith('/slow/')) {
      // mokapi's sleep() would block every other request: a timer only delays this one.
      await new Promise((resolve) => { setTimeout(resolve, AGENT_CALL_DELAY_SECONDS * 1000) })
    }
  })
}
