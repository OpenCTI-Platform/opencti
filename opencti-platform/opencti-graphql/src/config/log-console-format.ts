import { styleText } from 'node:util';
import { format } from 'winston';

type TextStyle = Parameters<typeof styleText>[0];

const LEVEL_STYLES: Record<string, TextStyle> = {
  error: ['bold', 'red'],
  warn: ['bold', 'yellow'],
  info: ['bold', 'blueBright'],
  http: ['bold', 'magenta'],
  verbose: ['bold', 'cyan'],
  debug: ['bold', 'magenta'],
  silly: ['bold', 'gray'],
};

// Metadata shown as [tags] on the first line instead of in the JSON, the keys of a same tag joined by a slash
const TAGS: { keys: string[]; style: TextStyle }[] = [
  { keys: ['version'], style: 'gray' },
  { keys: ['category'], style: 'green' },
  { keys: ['source', 'module', 'executionContext'], style: 'cyan' },
];
const TAG_KEYS = TAGS.flatMap(({ keys }) => keys);

// Colors are dropped automatically when stdout is not a TTY, unless FORCE_COLOR is set (see util.styleText)
export const formatPrettyLog = (info: Record<string, unknown>) => {
  const { level, message, timestamp, stack, ...fields } = info;
  const levelName = String(level);
  const tags = TAGS.map(({ keys, style }) => {
    const parts = keys.map((key) => fields[key]).filter((part) => part !== undefined);
    return parts.length > 0 ? styleText(style, `[${parts.join('/')}]`) : undefined;
  });
  const metadata = Object.fromEntries(Object.entries(fields).filter(([key]) => !TAG_KEYS.includes(key)));
  const firstLine = [
    timestamp ? styleText('dim', String(timestamp)) : undefined,
    styleText(LEVEL_STYLES[levelName] ?? 'bold', levelName),
    ...tags,
    message,
  ];
  const lines = [firstLine.filter((part) => part !== undefined).join(' ')];
  if (Object.keys(metadata).length > 0) {
    lines.push(JSON.stringify(metadata, null, 2));
  }
  // Error stacks are kept out of the JSON so their line breaks stay readable
  if (typeof stack === 'string') {
    lines.push(styleText('dim', stack));
  }
  return lines.join('\n');
};

export const prettyConsoleFormat = format.printf(formatPrettyLog);
