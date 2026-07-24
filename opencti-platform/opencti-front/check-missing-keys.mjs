import { readFileSync } from 'node:fs';

const keys = [
  'Academy',
  'Community edition',
  'Connected by',
  'Connection date',
  'Connection status',
  'Explore XTM Hub',
  'Extend and scale your OpenCTI experience',
  'Go to the Hub',
  'Not connected',
  'Pre-built content',
  'Try OpenCTI Enterprise Edition',
  'XTM Platform free trial',
  'XTM Platform Roadmap',
];
for (const lang of ['en', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'ru', 'zh']) {
  const json = JSON.parse(readFileSync(`lang/front/${lang}.json`, 'utf8'));
  const missing = keys.filter((k) => !(k in json));
  console.log(`${lang}: ${missing.length === 0 ? 'OK' : missing.join(' | ')}`);
}
