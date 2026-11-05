import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { extractDateStrings, guessPastDate } from '../../../src/intake/stix-import/dates';

// pycti OpenCTIStix2Utils.guess_past_date (datefinder 0.7.3 + dateutil 2.9) against its port.
// The expected values are pycti's own, written by client-python's
// python -m tests.import_conformance.generate (dates/expected.json, from dates/texts.json) with
// now = 2026-01-01T00:00:00+00:00 on a UTC host (TZ=UTC: dateutil maps the host's own zone names
// to its local zone), and checked by its --check. Two-digit years depend on the current year,
// as in dateutil. The port was also compared with pycti on 13,159 external reference texts of
// the benchmark corpus (MITRE ATT&CK, CVE) and on 100,000 random texts: no difference.

const DATES_DIR = join(__dirname, '../../../../../client-python/tests/data/import-conformance/dates');
const NOW = new Date('2026-01-01T00:00:00+00:00');

const PYCTI_GUESSES: { label: string; text: string; expected: string | null }[] = JSON.parse(readFileSync(join(DATES_DIR, 'expected.json'), 'utf-8'));

describe('guessPastDate: parity with pycti guess_past_date', () => {
  it('should read the table pycti computed', () => {
    expect(PYCTI_GUESSES.length).toBeGreaterThanOrEqual(58);
  });

  it.each(PYCTI_GUESSES.map((guess) => [guess.label, guess] as const))('%s', (_label, { text, expected }) => {
    expect(guessPastDate(text, NOW)).toEqual(expected);
  });

  it('gives no date for a missing or non-text value', () => {
    expect(guessPastDate(null, NOW)).toBeNull();
    expect(guessPastDate(undefined, NOW)).toBeNull();
    expect(guessPastDate(42 as unknown as string, NOW)).toBeNull();
  });
});

describe('extractDateStrings: datefinder candidates', () => {
  it('keeps the fragments of at least 3 captures, in order, sanitized', () => {
    expect(extractDateStrings('Hosseini, A. (2017, July 18). A Survey Of Things. Retrieved December 7, 2017.'))
      .toEqual(['2017, July 18', 'Of', 'December 7, 2017']);
    expect(extractDateStrings('https://github.com/201206030/novel-plus')).toEqual(['/201206030/nov']);
    expect(extractDateStrings('Monday')).toEqual([]);
  });

  it('splits ranges on to / through', () => {
    expect(extractDateStrings('From March 3, 2015 to April 5, 2016')).toEqual(['March 3, 2015', 'April 5, 2016']);
  });

  // The regexes are shared by every scan: a search that stops at its first date leaves its
  // position in the middle of a long text, the next scan of another text must not start there
  it('leaves no scan state behind when a search stops at its first date', () => {
    expect(guessPastDate('Hosseini, A. (2017, July 18). A Survey Of Things. Retrieved December 7, 2017.', NOW)).not.toBeNull();
    expect(extractDateStrings('July 18, 2017')).toEqual(['July 18, 2017']);
  });
});
