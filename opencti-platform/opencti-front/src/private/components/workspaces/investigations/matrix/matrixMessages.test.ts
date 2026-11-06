// The matrix counts use ICU plurals. A message that does not parse throws at render time (the app's
// IntlProvider rethrows every error but a missing translation), so each language is formatted here.
import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import de from '../../../../../../lang/front/de.json';
import en from '../../../../../../lang/front/en.json';
import es from '../../../../../../lang/front/es.json';
import fr from '../../../../../../lang/front/fr.json';
import it_ from '../../../../../../lang/front/it.json';
import ja from '../../../../../../lang/front/ja.json';
import ko from '../../../../../../lang/front/ko.json';
import ru from '../../../../../../lang/front/ru.json';
import zh from '../../../../../../lang/front/zh.json';

const LINKED = '{label}, linked to {count, plural, one {# entity} other {# entities}}';
const UNPLACED = '{count, plural, one {# attack pattern in this investigation isn\'t shown in this kill chain} other {# attack patterns in this investigation aren\'t shown in this kill chain}}';

const LANGUAGES: [string, Record<string, string>][] = [
  ['de-de', de], ['en-us', en], ['es-es', es], ['fr-fr', fr], ['it-it', it_],
  ['ja-jp', ja], ['ko-kr', ko], ['ru-ru', ru], ['zh-cn', zh],
];

const formatter = (locale: string, messages: Record<string, string>) => {
  const intl = createIntl({
    locale,
    messages,
    onError: (error) => {
      throw error;
    },
  });
  return (id: string, count: number) => intl.formatMessage({ id }, { label: 'T1059 - X', count });
};

describe('matrix count messages', () => {
  it.each(LANGUAGES)('%s translates and formats both counts for 0, 1, 2, 5 and 21', (locale, messages) => {
    expect(messages[LINKED]).toBeDefined();
    expect(messages[UNPLACED]).toBeDefined();
    const format = formatter(locale, messages);
    [0, 1, 2, 5, 21].forEach((count) => {
      expect(format(LINKED, count)).toContain(String(count));
      expect(format(UNPLACED, count)).toContain(String(count));
    });
  });

  it('reads as the PRD copy in English, singular for 1', () => {
    const format = formatter('en-us', en);
    expect(format(LINKED, 3)).toBe('T1059 - X, linked to 3 entities');
    expect(format(LINKED, 1)).toBe('T1059 - X, linked to 1 entity');
    expect(format(UNPLACED, 4)).toBe('4 attack patterns in this investigation aren\'t shown in this kill chain');
    expect(format(UNPLACED, 1)).toBe('1 attack pattern in this investigation isn\'t shown in this kill chain');
  });

  it('uses the Russian one, few and many forms', () => {
    const format = formatter('ru-ru', ru);
    expect(format(LINKED, 1)).toBe('T1059 - X, 1 связанная сущность');
    expect(format(LINKED, 3)).toBe('T1059 - X, 3 связанные сущности');
    expect(format(LINKED, 5)).toBe('T1059 - X, 5 связанных сущностей');
    expect(format(LINKED, 21)).toBe('T1059 - X, 21 связанная сущность');
  });
});
