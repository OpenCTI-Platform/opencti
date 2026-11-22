import { describe, expect, it } from 'vitest';
import { historyKindLabel, itemTitleText, triggerText } from './IrOutputCommon';

// A translator that marks what it translated and fills the values, so the test sees which key was used
const t = ((key: string, options?: { values?: Record<string, unknown> }) => {
  let text = `T[${key}]`;
  Object.entries(options?.values ?? {}).forEach(([name, value]) => {
    text = text.replace(`{${name}}`, String(value));
  });
  return text;
}) as never;

describe('triggerText', () => {
  it('rebuilds the engine triggers from their parts', () => {
    expect(triggerText(t, 'Entered through "Vulnerabilities"')).toBe('T[Entered through “Vulnerabilities”]');
    expect(triggerText(t, 'New proof through "Tools" (second hop)')).toBe('T[New proof through “Tools” (second hop)]');
    expect(triggerText(t, 'Updated: extensions, name')).toBe('T[Updated: extensions, name]');
    expect(triggerText(t, 'Configuration changed by admin')).toBe('T[Configuration changed by admin]');
    expect(triggerText(t, 'Rejected by admin')).toBe('T[Rejected by admin]');
    expect(triggerText(t, 'Accepted into the requirement by admin')).toBe('T[Accepted by admin]');
    expect(triggerText(t, 'Entity created')).toBe('T[Entity created]');
  });

  it('translates the relationship type of a relationship trigger', () => {
    expect(triggerText(t, 'New uses relationship')).toContain('T[New relationship:');
  });

  it('keeps an unknown trigger as stored and an empty one empty', () => {
    expect(triggerText(t, 'Something else')).toBe('Something else');
    expect(triggerText(t, null)).toBe('');
  });
});

describe('history and inbox wording', () => {
  it('labels each history kind', () => {
    expect(historyKindLabel(t, 'fact')).toBe('T[New fact]');
    expect(historyKindLabel(t, 'other')).toBe('other');
  });

  it('writes a score item without a threshold from the score reached', () => {
    const item = { item_kind: 'score', item_title: 'X crossed score 50', item_data: { to_score: 50 }, match: { entity: { representative: { main: 'X' } } } };
    expect(itemTitleText(t, item)).toBe('T[X reached a score of 50]');
  });
});
