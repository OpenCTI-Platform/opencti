import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TypeSafeClient } from '@typesafe-ai/sdk';
import { createJevClassifier } from './classifier.ts';
import type { Issue } from './issue.ts';
import { createLlmClassifier, parseAnswer } from './llm-classifier.ts';
import { resolveProvider } from './provider.ts';

const issue: Issue = { number: 7, title: 'fix(export): csv export is empty', body: 'The file has no rows.', labels: ['bug', 'export'] };

interface Call {
  url: string;
  body: any;
}

const fakeFetch = (calls: Call[], payload: unknown, status = 200) =>
  (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), body: JSON.parse(String(init?.body)) });
    return new Response(JSON.stringify(payload), { status, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;

test('jev: sends the prepared state and the taxonomy, maps the answers', async () => {
  const calls: Call[] = [];
  const client = new TypeSafeClient({
    apiKey: 'test',
    compression: false,
    fetch: fakeFetch(calls, {
      model: 'jev-1.13.0',
      usage: { input_tokens: 321, output_tokens: 3 },
      answers: {
        type: { type: 'choice', choice: 'bug', confidence: 0.97, probabilities: { bug: 0.97, feature: 0.03 } },
        area: { type: 'choice', choice: 'export', confidence: 0.8, probabilities: { export: 0.8, none: 0.2 } },
        needsMoreInfo: { type: 'noul', noul: 0.7 },
      },
    }),
  });

  const decision = await createJevClassifier({ client, model: 'jev-1.13.0' }).classify(issue);

  assert.equal(calls.length, 1);
  assert.match(calls[0]!.url, /\/v1\/systemone$/);
  assert.deepEqual(calls[0]!.body.state, { title: 'csv export is empty', body: 'The file has no rows.' });
  assert.equal(calls[0]!.body.model, 'jev-1.13.0');
  assert.ok('form intake' in calls[0]!.body.questions.area.criteria);
  assert.equal(decision.type.label, 'bug');
  assert.equal(decision.area.label, 'export');
  assert.equal(decision.area.confidence, 0.8);
  assert.equal(decision.needsMoreInfo, 0.7);
  assert.equal(decision.inputTokens, 321);
});

test('llm: calls chat completions and maps the JSON answer', async () => {
  const calls: Call[] = [];
  const content = JSON.stringify({ type: 'bug', typeConfidence: 0.9, area: 'export', areaConfidence: 0.7, needsMoreInfo: 0.1 });
  const classifier = createLlmClassifier({
    baseUrl: 'http://localhost:11434/v1/',
    model: 'some-model',
    fetch: fakeFetch(calls, { model: 'some-model:latest', choices: [{ message: { content } }], usage: { prompt_tokens: 512 } }),
  });

  const decision = await classifier.classify(issue);

  assert.equal(calls[0]!.url, 'http://localhost:11434/v1/chat/completions');
  assert.equal(calls[0]!.body.messages[1].content, JSON.stringify({ title: 'csv export is empty', body: 'The file has no rows.' }));
  assert.deepEqual(decision.type, { label: 'bug', confidence: 0.9, probabilities: { bug: 0.9 } });
  assert.equal(decision.area.label, 'export');
  assert.equal(decision.model, 'some-model:latest');
  assert.equal(decision.inputTokens, 512);
});

test('llm: an answer off the taxonomy or a failed call is an error', async () => {
  assert.throws(() => parseAnswer('{"type":"enhancement","typeConfidence":1,"area":"none","areaConfidence":1,"needsMoreInfo":0}'), /"type" is not a known label/);
  assert.throws(() => parseAnswer('{"type":"toString","typeConfidence":1,"area":"none","areaConfidence":1,"needsMoreInfo":0}'), /"type" is not a known label/);
  assert.throws(() => parseAnswer('{"type":"bug","typeConfidence":"high","area":"none","areaConfidence":1,"needsMoreInfo":0}'), /"typeConfidence"/);
  const failing = createLlmClassifier({ baseUrl: 'http://x/v1', model: 'm', fetch: fakeFetch([], { error: 'nope' }, 500) });
  await assert.rejects(failing.classify(issue), /LLM call failed: 500/);
});

test('provider: explicit choice wins, then Jev, then the LLM, else none', () => {
  assert.equal(resolveProvider({ TRIAGE_PROVIDER: 'llm', TYPESAFE_API_KEY: 'k', LLM_MODEL: 'm' }), 'llm');
  assert.equal(resolveProvider({ TYPESAFE_API_KEY: 'k', LLM_MODEL: 'm' }), 'jev');
  assert.equal(resolveProvider({ LLM_MODEL: 'm' }), 'llm');
  assert.equal(resolveProvider({}), undefined);
  assert.throws(() => resolveProvider({ TRIAGE_PROVIDER: 'gpt' }), /must be "jev" or "llm"/);
});
