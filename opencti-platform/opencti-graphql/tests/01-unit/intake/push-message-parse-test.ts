import { afterEach, describe, expect, it, vi } from 'vitest';
import { parsePushMessage } from '../../../src/intake/workerless/push-intake';

// Oracle for parsePushMessage on the raw message bytes (content sliced out, the rest parsed): the
// former decode, body.toString() then JSON.parse of everything (push-consumer.ts + push-intake.ts
// as of b48f3c0250, copied below), must give the same object, keys in the same order, on every body.

// ---- reference: the parse before the rewrite ----
const parseOld = (body: string): Record<string, any> | null => {
  try {
    const data = JSON.parse(body);
    return data !== null && typeof data === 'object' ? data : null;
  } catch {
    return null;
  }
};

const lcg = (seed: number) => {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
};

// pycti json.dumps: ', ' and ': ' separators, non-ASCII escaped (ensure_ascii)
const pyDumps = (value: unknown) => JSON.stringify(value)
  .replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
  .replace(/":/g, '": ')
  .replace(/,"/g, ', "');

// a Buffer at an arbitrary offset of a larger one (amqplib slices frames): exercises the alignment
const atOffset = (bytes: Buffer, offset: number) => {
  const host = Buffer.alloc(bytes.length + offset + 3, 0x41);
  bytes.copy(host, offset);
  return host.subarray(offset, offset + bytes.length);
};

const same = (body: Buffer) => {
  const expected = parseOld(body.toString());
  const actual = parsePushMessage(body);
  return JSON.stringify(actual) === JSON.stringify(expected) && (actual === null) === (expected === null);
};

const base64Of = (rnd: () => number, size: number) => {
  const bytes = Buffer.alloc(size);
  for (let i = 0; i < size; i += 1) bytes[i] = Math.floor(rnd() * 256);
  return bytes.toString('base64');
};

// One random envelope body, plain or tricky
const randomBody = (rnd: () => number): Buffer => {
  const pick = <T>(values: T[]): T => values[Math.floor(rnd() * values.length)];
  const fields: [string, unknown][] = [
    ['bundle_type', 'QUEUE_BUNDLE'],
    ['applicant_id', pick(['88ec0c6a-13ce-5e39-b486-354fe4a7084f', 'é-user', 'x"content": "y', '\\"content\\": "zz', 'emoji 😀', ''])],
    ['action_sequence', Math.floor(rnd() * 10)],
    ['entities_types', pick([[], ['Report'], ['content']])],
    ['update', rnd() < 0.5],
    ['draft_id', pick(['', null, 'draft'])],
    ['no_split', false],
    ['type', pick(['bundle', 'event', undefined])],
  ];
  if (rnd() < 0.15) fields.push(['meta', { content: base64Of(rnd, 6), note: 'nested' }]);
  if (rnd() < 0.05) fields.push(['list', [{ content: 'QQ==' }]]);
  const contentShape = rnd();
  let content: unknown;
  if (contentShape < 0.6) content = base64Of(rnd, Math.floor(rnd() * (rnd() < 0.1 ? 60000 : 300)));
  else if (contentShape < 0.65) content = base64Of(rnd, Math.floor(rnd() * 3)); // '' or one quad
  else if (contentShape < 0.7) content = pick([12, null, true, { a: 1 }, ['QQ==']]);
  else if (contentShape < 0.75) content = undefined; // missing
  else if (contentShape < 0.8) content = `${base64Of(rnd, 30)}é`; // non-ASCII in the value
  else if (contentShape < 0.85) content = `QUJD/${base64Of(rnd, 9)}`; // a '/' a writer may escape
  else content = base64Of(rnd, 40);
  const entries = fields.filter(([, v]) => v !== undefined);
  if (content !== undefined) entries.splice(Math.floor(rnd() * (entries.length + 1)), 0, ['content', content]);
  const object = Object.fromEntries(entries);
  const style = rnd();
  let text: string;
  if (style < 0.4) text = pyDumps(object);
  else if (style < 0.7) text = JSON.stringify(object);
  else if (style < 0.85) text = JSON.stringify(object, null, rnd() < 0.5 ? 2 : '\t');
  else text = ` \n${JSON.stringify(object).replace(/":/g, '" :\t').replace(/,"/g, ',\r\n "')}\n`;
  // raw-text mutations the object cannot express
  const mutation = rnd();
  if (mutation < 0.05) text = text.replace('"content"', '"\\u0063ontent"'); // escaped key
  else if (mutation < 0.1) text = text.replace(/}\s*$/, ', "content": "QQ=="}'); // duplicate key, last wins
  else if (mutation < 0.15) text = text.replace('QUJD/', 'QUJD\\/'); // escape in the value
  else if (mutation < 0.2 && typeof content === 'string' && content.length > 4) {
    text = text.replace(content, `${content.slice(0, 2)}${pick(['\u0001', '\t', '\n', '\u001f', '\u007f'])}${content.slice(2)}`); // raw byte in the value
  } else if (mutation < 0.23) text = text.slice(0, Math.floor(rnd() * text.length)); // truncated
  else if (mutation < 0.25) text = `[${text}]`; // not an object
  else if (mutation < 0.27) text = `\ufeff${text}`; // BOM
  else if (mutation < 0.3) text = text.replace('"meta"', '"me\\"content\\"ta"');
  let bytes = Buffer.from(text);
  // an invalid UTF-8 byte outside the value
  if (rnd() < 0.03) bytes = Buffer.concat([bytes.subarray(0, 3), Buffer.from([0xff]), bytes.subarray(3)]);
  return atOffset(bytes, Math.floor(rnd() * 4));
};

describe('parsePushMessage oracle: content sliced from the raw bytes', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should parse 20,000 random envelopes exactly as body.toString() + JSON.parse', () => {
    const rnd = lcg(17);
    const differing: string[] = [];
    // bodies parsed without the content in the JSON.parse text: the sliced path, not the fallback
    const parse = vi.spyOn(JSON, 'parse');
    let sliced = 0;
    for (let k = 0; k < 20000; k += 1) {
      const body = randomBody(rnd);
      parse.mockClear();
      if (!same(body)) differing.push(body.toString().slice(0, 200));
      if (parse.mock.calls.some(([text]) => String(text).length < body.toString().length - 2)) sliced += 1;
    }
    expect(differing).toEqual([]);
    expect(sliced).toBeGreaterThan(5000);
  });

  it('should parse the tricky shapes exactly as the full parse', () => {
    const b64 = Buffer.from('a bundle').toString('base64');
    const bodies = [
      `{"content": "${b64}", "type": "bundle"}`,
      `{"type": "event", "content": "${b64}"}`,
      `{"content":"${b64}","content":"QQ=="}`,
      '{"meta":{"content":"QQ=="},"\\u0063ontent":""}',
      // a nested "content" met first, the top-level one empty: only the second occurrence tells
      '{"meta":{"content":"QQ=="},"content":""}',
      '{"meta":{"content":"QQ=="},"x":1}',
      `{"a":"x,\\"content\\": \\"y","content":"${b64}"}`,
      '{"content": "QUJD\\u0044", "x": 1}',
      '{"content": "QUJDé==", "x": 1}',
      '{"content": "QU\u0001JD", "x": 1}',
      '{"content": "QU\u007fJD", "x": 1}',
      '{"content": 12, "x": 1}',
      '{"content": "", "x": 1}',
      '{"x": "\\u00e9", "content": "QQ=="}',
      '{"content": "QQ==", "x": "é"}',
      '{"content": "QQ==" , "x": 1 }',
      '{"content"\n:\n"QQ=="}',
      '[{"content": "QQ=="}]',
      '{"content": "QQ==", "x": }',
      '{"content": "QQ==',
      '"content"',
      'null',
      '',
    ];
    bodies.forEach((text) => {
      for (let offset = 0; offset < 4; offset += 1) expect(same(atOffset(Buffer.from(text), offset)), text).toBe(true);
    });
    // a string body keeps the former behavior
    bodies.forEach((text) => expect(JSON.stringify(parsePushMessage(text)), text).toBe(JSON.stringify(parseOld(text))));
  });

  it('should not JSON.parse the content of a pycti envelope', () => {
    const content = Buffer.alloc(300_000, 9).toString('base64');
    const body = Buffer.from(pyDumps({ bundle_type: 'QUEUE_BUNDLE', applicant_id: 'a', action_sequence: 1, entities_types: [], content, update: false, draft_id: '', no_split: false }));
    const parse = vi.spyOn(JSON, 'parse');
    const data = parsePushMessage(body);
    expect(data?.content).toBe(content);
    expect(Object.keys(data ?? {})).toEqual(['bundle_type', 'applicant_id', 'action_sequence', 'entities_types', 'content', 'update', 'draft_id', 'no_split']);
    expect(parse.mock.calls.every(([text]) => String(text).length < 1000)).toBe(true);
  });
});
