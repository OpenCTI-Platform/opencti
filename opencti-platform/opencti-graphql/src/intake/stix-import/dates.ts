// pycti OpenCTIStix2Utils.guess_past_date: the first date older than a day found in a free text
// (an external reference description or source name), as %Y-%m-%dT%H:%M:%SZ.
//
// pycti runs the datefinder library (0.7.3) with base_date = 1970-01-01, which itself runs
// dateutil.parser.parse (2.9) on each candidate. Both are ported here, limited to what pycti
// reaches:
// - pycti patches `datefinder.ValueError = ValueError, OverflowError`. In datefinder's
//   `except (ValueError, OverflowError)` that makes a nested tuple, which Python 3 refuses with a
//   TypeError as soon as an exception reaches the clause. So the first candidate dateutil cannot
//   parse ends the whole search with no result (guess_past_date catches the TypeError), and
//   datefinder's fallback (token replacements, time zone names, second parse) never runs: it is
//   not ported. A text like "Based on the report. Retrieved May 3, 2017." gives no date, its
//   " on " fragment comes first and dateutil rejects it.
// - Candidates: datefinder's regular expression (no word boundaries, alternatives in the same
//   order), its range split on " to " / " through ", the fragments of at least 3 captures.
// - Parse: dateutil's lexer and non-fuzzy parser with the default parserinfo (English, month
//   first), missing parts taken from 1970-01-01T00:00:00, a weekday without a day moved forward.
//   Two-digit years use the current local year of the host, as dateutil does (not `now`).
// - Time zones: UTC/GMT/Z and numeric offsets convert to UTC; other names are ignored (naive),
//   as dateutil does without tzinfos. Names of the host's local zone (dateutil maps them to its
//   local zone) are those of a UTC host: on a non-UTC host pycti would shift e.g. "10:30 CET".
// - Unicode: \d, \s and \W follow the `regex` module (Unicode digits are read as digits, as
//   Python's int does).
// Not reproduced: the host time zone of pycti when it is not UTC (see above), the Python 2 /
// older Python behaviour where the patched except clause would catch, characters newer than
// the Unicode tables of Node (the `regex` module ships newer ones).

import { asciiDigits, isPythonSpace } from './utils';

const EPOCH_YEAR = 1970;
const STRIP_CHARS = ' \n\t:-.,_';

// --- datefinder constants (datefinder/constants.py), verbatim

const NUMBERS_PATTERN = 'first|second|third|fourth|fifth|sixth|seventh|eighth|nineth|tenth';
const POSITIONNAL_TOKENS = 'next|last';
const DIGITS_SUFFIXES = 'st|th|rd|nd';
const DAYS_PATTERN = 'monday|tuesday|wednesday|thursday|friday|saturday|sunday|mandag|tirsdag|onsdag|torsdag|fredag|lørdag|søndag|mon|tue|tues|wed|thu|thur|thurs|fri|sat|sun|man|tir|tirs|ons|tor|tors|fre|lør|søn';
const MONTHS_PATTERN = 'january|february|march|april|may|june|july|august|september|october|november|december|enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre|januar|februar|marts|april|maj|juni|juli|august|september|oktober|november|december|jan\\.?|ene\\.?|feb\\.?|mar\\.?|apr\\.?|abr\\.?|may\\.?|maj\\.?|jun\\.?|jul\\.?|aug\\.?|ago\\.?|sep\\.?|sept\\.?|oct\\.?|okt\\.?|nov\\.?|dec\\.?|dic\\.?';
const TIMEZONES_PATTERN = 'ACDT|ACST|ACT|ACWDT|ACWST|ADDT|ADMT|ADT|AEDT|AEST|AFT|AHDT|AHST|AKDT|AKST|AKTST|AKTT|ALMST|ALMT|AMST|AMT|ANAST|ANAT|ANT|APT|AQTST|AQTT|ARST|ART|ASHST|ASHT|AST|AWDT|AWST|AWT|AZOMT|AZOST|AZOT|AZST|AZT|BAKST|BAKT|BDST|BDT|BEAT|BEAUT|BIOT|BMT|BNT|BORT|BOST|BOT|BRST|BRT|BST|BTT|BURT|CANT|CAPT|CAST|CAT|CAWT|CCT|CDDT|CDT|CEDT|CEMT|CEST|CET|CGST|CGT|CHADT|CHAST|CHDT|CHOST|CHOT|CIST|CKHST|CKT|CLST|CLT|CMT|COST|COT|CPT|CST|CUT|CVST|CVT|CWT|CXT|ChST|DACT|DAVT|DDUT|DFT|DMT|DUSST|DUST|EASST|EAST|EAT|ECT|EDDT|EDT|EEDT|EEST|EET|EGST|EGT|EHDT|EMT|EPT|EST|ET|EWT|FET|FFMT|FJST|FJT|FKST|FKT|FMT|FNST|FNT|FORT|FRUST|FRUT|GALT|GAMT|GBGT|GEST|GET|GFT|GHST|GILT|GIT|GMT|GST|GYT|HAA|HAC|HADT|HAE|HAP|HAR|HAST|HAT|HAY|HDT|HKST|HKT|HLV|HMT|HNA|HNC|HNE|HNP|HNR|HNT|HNY|HOVST|HOVT|HST|ICT|IDDT|IDT|IHST|IMT|IOT|IRDT|IRKST|IRKT|IRST|ISST|IST|JAVT|JCST|JDT|JMT|JST|JWST|KART|KDT|KGST|KGT|KIZST|KIZT|KMT|KOST|KRAST|KRAT|KST|KUYST|KUYT|KWAT|LHDT|LHST|LINT|LKT|LMT|LMT|LMT|LMT|LRT|LST|MADMT|MADST|MADT|MAGST|MAGT|MALST|MALT|MART|MAWT|MDDT|MDST|MDT|MEST|MET|MHT|MIST|MIT|MMT|MOST|MOT|MPT|MSD|MSK|MSM|MST|MUST|MUT|MVT|MWT|MYT|NCST|NCT|NDDT|NDT|NEGT|NEST|NET|NFT|NMT|NOVST|NOVT|NPT|NRT|NST|NT|NUT|NWT|NZDT|NZMT|NZST|OMSST|OMST|ORAST|ORAT|PDDT|PDT|PEST|PET|PETST|PETT|PGT|PHOT|PHST|PHT|PKST|PKT|PLMT|PMDT|PMMT|PMST|PMT|PNT|PONT|PPMT|PPT|PST|PT|PWT|PYST|PYT|QMT|QYZST|QYZT|RET|RMT|ROTT|SAKST|SAKT|SAMT|SAST|SBT|SCT|SDMT|SDT|SET|SGT|SHEST|SHET|SJMT|SLT|SMT|SRET|SRT|SST|STAT|SVEST|SVET|SWAT|SYOT|TAHT|TASST|TAST|TBIST|TBIT|TBMT|TFT|THA|TJT|TKT|TLT|TMT|TOST|TOT|TRST|TRT|TSAT|TVT|ULAST|ULAT|URAST|URAT|UTC|UYHST|UYST|UYT|UZST|UZT|VET|VLAST|VLAT|VOLST|VOLT|VOST|VUST|VUT|WARST|WART|WAST|WAT|WDT|WEDT|WEMT|WEST|WET|WFT|WGST|WGT|WIB|WIT|WITA|WMT|WSDT|WSST|WST|WT|XJT|YAKST|YAKT|YAPT|YDDT|YDT|YEKST|YEKST|YEKT|YEKT|YERST|YERT|YPT|YST|YWT|zzz';
const NA_TIMEZONES_PATTERN = 'pacific|eastern|mountain|central';
const ALL_TIMEZONES_PATTERN = `${TIMEZONES_PATTERN}|${NA_TIMEZONES_PATTERN}`;
const TIME_PERIOD_PATTERN = 'a\\.m\\.|am|p\\.m\\.|pm';
const EXTRA_TOKENS_PATTERN = 'due|by|on|during|standard|daylight|savings|time|date|dated|of|to|through|between|until|at|day';

// Python `regex` Unicode classes: \d is \p{Nd}, \s is White_Space, \w the Unicode word class
const D = '\\p{Nd}';
const WS = '[\\t\\n\\v\\f\\r \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]';
const NON_WORD = '[^\\p{Alphabetic}\\p{M}\\p{Nd}\\p{Pc}\\p{Join_Control}]';
const DELIMITERS_PATTERN = '[/:\\-,.\\t\\n\\v\\f\\r \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000_+@]+';

const MONTH_NUMBERS = Array.from({ length: 12 }, (_, index) => String(index + 1).padStart(2, '0'));
const YYYY_PATTERN = `19${D}${D}|20${D}${D}`;
const YYYYMM_PATTERN = MONTH_NUMBERS.map((month) => `19${D}${D}${month}|20${D}${D}${month}`).join('|');
const YYYYMMDD_PATTERN = MONTH_NUMBERS.map((month) => `19${D}${D}${month}[0123]${D}|20${D}${D}${month}[0123]${D}`).join('|');
const YYYYMMDDHHMMSS_PATTERN = MONTH_NUMBERS
  .map((month) => `19${D}${D}${month}[0-3]${D}[0-5]${D}[0-5]${D}[0-5]${D}|20${D}${D}${month}[0-3]${D}[0-5]${D}[0-5]${D}[0-5]${D}`)
  .join('|');
// The groups of the same name in several alternatives are suffixed (JS refuses duplicates):
// each one counts as a capture of its datefinder group
const ISO8601_PATTERN = '(?<iso_years>-?(:[1-9][0-9]*)?[0-9]{4})-(?<iso_months>1[0-2]|0[1-9])-(?<iso_days>3[01]|0[1-9]|[12][0-9])'
  + 'T(?<iso_hours>2[0-3]|[01][0-9]):(?<iso_minutes>[0-5][0-9]):(?<iso_seconds>[0-5][0-9])(?:[.,]+(?<iso_microseconds>[0-9]+))?'
  + '(?<iso_offset>(?:Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9]))?';
const UNDELIMITED_STAMPS_PATTERN = [YYYYMMDDHHMMSS_PATTERN, YYYYMMDD_PATTERN, YYYYMM_PATTERN, ISO8601_PATTERN].join('|');
const TIME_PATTERN = '(?<time>'
  + `(?<hours1>${D}{1,2}):(?<minutes1>${D}{1,2})(?::(?<seconds1>${D}{1,2}))?(?:[.,](?<microseconds1>${D}{1,6}))?`
  + `${WS}*(?<time_periods1>${TIME_PERIOD_PATTERN})?${WS}*(?<timezones1>${ALL_TIMEZONES_PATTERN})?`
  + '|'
  + `(?<hours2>${D}{1,2})${WS}*(?<time_periods2>${TIME_PERIOD_PATTERN})${WS}*(?<timezones2>(?:${ALL_TIMEZONES_PATTERN})*)`
  + ')';
const DATES_PATTERN = `(?<undelimited_stamps>${UNDELIMITED_STAMPS_PATTERN})`
  + `|${TIME_PATTERN}`
  + `|(?<years>${YYYY_PATTERN})`
  + `|(?<numbers>${NUMBERS_PATTERN})`
  + `|(?<digits>${D}+)(?<digits_suffixes>${DIGITS_SUFFIXES})?`
  + `|(?<days>${DAYS_PATTERN})`
  + `|(?<months>${MONTHS_PATTERN})`
  + `|(?<delimiters>${DELIMITERS_PATTERN})`
  + `|(?<positionnal_tokens>${POSITIONNAL_TOKENS})`
  + `|(?<extra_tokens>${EXTRA_TOKENS_PATTERN})`;

// DATE_REGEX and RANGE_SPLIT_REGEX are scanned with exec from a position kept by the caller
// (matchAll would clone the large DATE_REGEX on every call). Neither can match the empty string:
// every alternative of DATES_PATTERN consumes at least one character, RANGE_SPLIT_REGEX consumes
// its NON_WORD characters, and neither has a lookaround, anchor or \b. So the scan never needs
// matchAll's step over an empty match.
const DATE_REGEX = new RegExp(DATES_PATTERN, 'giu');
// Every named group of DATES_PATTERN: JavaScript lists all of them in `groups`, matched or not
const DATE_GROUP_NAMES = Object.keys(new RegExp(DATES_PATTERN, 'u').exec('1')?.groups ?? {});
// Without the names, no match would count a capture and no date would ever be found
if (DATE_GROUP_NAMES.length === 0) {
  throw new Error('DATES_PATTERN must match "1" to list its named groups');
}
const REPEATED_TIMEZONE_REGEX = new RegExp(`(?:${ALL_TIMEZONES_PATTERN})`, 'iuy');
const RANGE_SPLIT_REGEX = new RegExp(`${NON_WORD}to${NON_WORD}|${NON_WORD}through${NON_WORD}`, 'giu');
// datefinder `[\n\t\s\xa0]+`
const WHITESPACE_RUN_REGEX = new RegExp(`(?:${WS}|[\\n\\t\\xa0])+`, 'gu');

// The captures of one match, as datefinder sums them (capturesdict of every named group)
const capturesCount = (groups: Record<string, string | undefined>) => {
  let count = 0;
  for (const name of DATE_GROUP_NAMES) {
    const value = groups[name];
    if (value === undefined) {
      continue;
    }
    if (name === 'timezones2') {
      // (?P<timezones>...)* captures once per repetition
      REPEATED_TIMEZONE_REGEX.lastIndex = 0;
      while (REPEATED_TIMEZONE_REGEX.lastIndex < value.length && REPEATED_TIMEZONE_REGEX.test(value)) {
        count += 1;
      }
    } else {
      count += 1;
    }
  }
  return count;
};

const pyStrip = (value: string, chars: string) => {
  let start = 0;
  let end = value.length;
  while (start < end && chars.includes(value[start])) {
    start += 1;
  }
  while (end > start && chars.includes(value[end - 1])) {
    end -= 1;
  }
  return value.slice(start, end);
};

// The next match of a global regex from a position, whatever lastIndex was left at
const execAt = (regex: RegExp, text: string, position: number) => {
  regex.lastIndex = position;
  return regex.exec(text);
};

// datefinder DateFinder.tokenize_string and merge_tokens: runs of adjacent matches with at
// least 3 captures in all. A generator: the scan position lives here, not in DATE_REGEX, so a
// scan left suspended or abandoned by its consumer leaves nothing behind.
function* extractFragments(text: string): Generator<string> {
  let current = '';
  let count = 0;
  let lastIndex = 0;
  for (let match = execAt(DATE_REGEX, text, 0); match !== null; match = execAt(DATE_REGEX, text, lastIndex)) {
    if (match.index > lastIndex) {
      if (count >= 3) {
        yield current;
      }
      current = '';
      count = 0;
    }
    current += match[0];
    count += capturesCount(match.groups as Record<string, string | undefined>);
    lastIndex = match.index + match[0].length;
  }
  if (count >= 3) {
    yield current;
  }
}

// datefinder DateFinder.split_date_range
const splitDateRange = (text: string): string[] => {
  const parts: string[] = [];
  let start = 0;
  for (let match = execAt(RANGE_SPLIT_REGEX, text, 0); match !== null; match = execAt(RANGE_SPLIT_REGEX, text, start)) {
    const matchStart = match.index;
    if (matchStart > start) {
      parts.push(text.slice(start, matchStart));
    }
    start = matchStart + match[0].length;
  }
  if (start < text.length) {
    parts.push(text.slice(start));
  }
  return parts;
};

// datefinder DateFinder.extract_date_strings_inner (sanitized candidates, in order). Lazy, as
// datefinder is: the extraction has no side effect, so guessPastDate stops reading the text at
// its first decisive candidate.
function* dateCandidates(text: string): Generator<string> {
  const range = splitDateRange(text);
  if (range.length > 1) {
    for (const part of range) {
      yield* dateCandidates(part);
    }
    return;
  }
  for (const fragment of extractFragments(text)) {
    yield pyStrip(fragment.replace(WHITESPACE_RUN_REGEX, ' '), STRIP_CHARS);
  }
}

export const extractDateStrings = (text: string): string[] => [...dateCandidates(text)];

// --- dateutil.parser (dateutil/parser/_parser.py), non-fuzzy, default parserinfo

class ParseError extends Error {}

const fail = (message: string): never => {
  throw new ParseError(message);
};

const LETTER = /^\p{L}$/u;
const DIGIT = /^\p{Nd}$/u;

const countDots = (value: string) => value.split('.').length - 1;

// dateutil _timelex.split
const timelexSplit = (input: string): string[] => {
  const chars = Array.from(input).filter((char) => char !== '\x00');
  let position = 0;
  const charStack: string[] = [];
  const tokenStack: string[] = [];
  let eof = false;
  const isWord = (char: string) => LETTER.test(char);
  const isNum = (char: string) => DIGIT.test(char);
  const getToken = (): string | null => {
    if (tokenStack.length > 0) {
      return tokenStack.shift() as string;
    }
    let seenLetters = false;
    let token: string | null = null;
    let state: string | null = null;
    while (!eof) {
      let nextChar: string;
      if (charStack.length > 0) {
        nextChar = charStack.shift() as string;
      } else {
        nextChar = position < chars.length ? chars[position] : '';
        position += 1;
      }
      if (!nextChar) {
        eof = true;
        break;
      } else if (!state) {
        token = nextChar;
        if (isWord(nextChar)) {
          state = 'a';
        } else if (isNum(nextChar)) {
          state = '0';
        } else if (isPythonSpace(nextChar)) {
          token = ' ';
          break;
        } else {
          break;
        }
      } else if (state === 'a') {
        seenLetters = true;
        if (isWord(nextChar)) {
          token += nextChar;
        } else if (nextChar === '.') {
          token += nextChar;
          state = 'a.';
        } else {
          charStack.push(nextChar);
          break;
        }
      } else if (state === '0') {
        if (isNum(nextChar)) {
          token += nextChar;
        } else if (nextChar === '.' || (nextChar === ',' && (token as string).length >= 2)) {
          token += nextChar;
          state = '0.';
        } else {
          charStack.push(nextChar);
          break;
        }
      } else if (state === 'a.') {
        seenLetters = true;
        if (nextChar === '.' || isWord(nextChar)) {
          token += nextChar;
        } else if (isNum(nextChar) && (token as string).endsWith('.')) {
          token += nextChar;
          state = '0.';
        } else {
          charStack.push(nextChar);
          break;
        }
      } else if (state === '0.') {
        if (nextChar === '.' || isNum(nextChar)) {
          token += nextChar;
        } else if (isWord(nextChar) && (token as string).endsWith('.')) {
          token += nextChar;
          state = 'a.';
        } else {
          charStack.push(nextChar);
          break;
        }
      }
    }
    if ((state === 'a.' || state === '0.') && token !== null
      && (seenLetters || countDots(token) > 1 || '.,'.includes(token[token.length - 1]))) {
      const parts = token.split(/([.,])/);
      [token] = parts;
      parts.slice(1).forEach((part) => {
        if (part) {
          tokenStack.push(part);
        }
      });
    }
    if (state === '0.' && token !== null && countDots(token) === 0) {
      token = token.replace(/,/g, '.');
    }
    return token;
  };
  const tokens: string[] = [];
  for (let token = getToken(); token !== null; token = getToken()) {
    tokens.push(token);
  }
  return tokens;
};

const JUMP = new Set([' ', '.', ',', ';', '-', '/', '\'', 'at', 'on', 'and', 'ad', 'm', 't', 'of', 'st', 'nd', 'rd', 'th']);
const WEEKDAYS: Record<string, number> = {};
[['mon', 'monday'], ['tue', 'tuesday'], ['wed', 'wednesday'], ['thu', 'thursday'], ['fri', 'friday'], ['sat', 'saturday'], ['sun', 'sunday']]
  .forEach((names, index) => names.forEach((name) => {
    WEEKDAYS[name] = index;
  }));
const MONTHS: Record<string, number> = {};
[['jan', 'january'], ['feb', 'february'], ['mar', 'march'], ['apr', 'april'], ['may'], ['jun', 'june'], ['jul', 'july'], ['aug', 'august'],
  ['sep', 'sept', 'september'], ['oct', 'october'], ['nov', 'november'], ['dec', 'december']]
  .forEach((names, index) => names.forEach((name) => {
    MONTHS[name] = index + 1;
  }));
const HMS: Record<string, number> = { h: 0, hour: 0, hours: 0, m: 1, minute: 1, minutes: 1, s: 2, second: 2, seconds: 2 };
const AMPM: Record<string, number> = { am: 0, a: 0, pm: 1, p: 1 };
const UTCZONE = ['UTC', 'GMT', 'Z', 'z'];
// time.tzname of the host: a UTC host (the platform runs in UTC containers)
const LOCAL_TZ_NAMES = ['UTC', 'UTC'];

const lookup = (table: Record<string, number>, name: string): number | null => {
  const key = name.toLowerCase();
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : null;
};
const isJump = (name: string) => JUMP.has(name.toLowerCase());
const isPertain = (name: string) => name.toLowerCase() === 'of';
const isUtcZone = (name: string) => ['utc', 'gmt', 'z'].includes(name.toLowerCase());
const infoTzOffset = (name: string) => (['utc', 'gmt', 'z'].includes(name) ? 0 : null);
const isDigitString = (value: string) => value.length > 0 && Array.from(value).every((char) => DIGIT.test(char));

// Python int() of a string (whitespace, sign, digits with single underscores)
const pyInt = (value: string): number => {
  const match = /^\s*([+-]?)(\d+(?:_\d+)*)\s*$/.exec(value);
  if (!match) {
    return fail(`invalid literal for int(): '${value}'`);
  }
  const parsed = Number(match[2].replace(/_/g, ''));
  return match[1] === '-' ? -parsed : parsed;
};

// Python list indexing, negative indexes from the end, IndexError out of range
const at = <T>(list: T[], index: number): T => {
  const position = index < 0 ? list.length + index : index;
  if (position < 0 || position >= list.length) {
    return fail('list index out of range');
  }
  return list[position];
};

// A Decimal of a numeric token: digits with an optional fraction, kept exact
interface Decimal {
  integer: number;
  fraction: string;
  value: number;
}

const toDecimal = (value: string): Decimal => {
  const match = /^(\d*)(?:\.(\d*))?$/.exec(value);
  if (!match || (match[1] === '' && (match[2] ?? '') === '')) {
    return fail(`Could not convert ${value} to decimal`);
  }
  return { integer: Number(match[1] || '0'), fraction: match[2] ?? '', value: Number(`${match[1] || '0'}.${match[2] || '0'}`) };
};
// Python float() of a token: the numeric tokens, and the words nan / inf / infinity
const isFloat = (value: string) => /^(\d+(\.\d*)?|\.\d+)$/.test(value) || /^(nan|inf|infinity)$/i.test(value);
const hasFraction = (decimal: Decimal) => /[1-9]/.test(decimal.fraction);
// int(60 * (value % 1)), exact
const sixtiethsOf = (decimal: Decimal) => {
  if (!hasFraction(decimal)) {
    return 0;
  }
  return Number((60n * BigInt(decimal.fraction)) / (10n ** BigInt(decimal.fraction.length)));
};

interface ParseResult {
  year: number | null;
  month: number | null;
  day: number | null;
  weekday: number | null;
  hour: number | null;
  minute: number | null;
  second: number | null;
  microsecond: number | null;
  tzname: string | null;
  tzoffset: number | null;
  ampm: number | null;
  centurySpecified: boolean;
}

// dateutil _ymd
class Ymd {
  values: number[] = [];

  centurySpecified = false;

  dstridx: number | null = null;

  mstridx: number | null = null;

  ystridx: number | null = null;

  get length() {
    return this.values.length;
  }

  couldBeDay(value: number) {
    if (this.dstridx !== null) {
      return false;
    }
    if (this.mstridx === null) {
      return value >= 1 && value <= 31;
    }
    const month = this.values[this.mstridx];
    const year = this.ystridx === null ? 2000 : this.values[this.ystridx];
    return value >= 1 && value <= daysInMonth(year, month);
  }

  append(input: string | number | Decimal, inputLabel: string | null = null) {
    let label = inputLabel;
    let value: number;
    if (typeof input === 'string') {
      if (isDigitString(input) && Array.from(input).length > 2) {
        this.centurySpecified = true;
        label = 'Y';
      }
      value = pyInt(input);
    } else {
      const number = typeof input === 'number' ? input : input.value;
      if (number > 100) {
        this.centurySpecified = true;
        label = 'Y';
      }
      value = typeof input === 'number' ? Math.trunc(input) : input.integer;
    }
    this.values.push(value);
    if (label === 'M') {
      if (this.mstridx !== null) {
        fail('Month is already set');
      }
      this.mstridx = this.values.length - 1;
    } else if (label === 'D') {
      if (this.dstridx !== null) {
        fail('Day is already set');
      }
      this.dstridx = this.values.length - 1;
    } else if (label === 'Y') {
      if (this.ystridx !== null) {
        fail('Year is already set');
      }
      this.ystridx = this.values.length - 1;
    }
  }

  resolveFromStridxs(strids: Map<string, number>): [number | null, number | null, number | null] {
    if (this.values.length === 3 && strids.size === 2) {
      const used = [...strids.values()];
      const missing = [0, 1, 2].filter((index) => !used.includes(index));
      const keys = ['y', 'm', 'd'].filter((key) => !strids.has(key));
      if (missing.length !== 1 || keys.length !== 1) {
        fail('AssertionError');
      }
      strids.set(keys[0], missing[0]);
    }
    if (this.values.length !== strids.size) {
      fail('AssertionError');
    }
    const get = (key: string) => (strids.has(key) ? this.values[strids.get(key) as number] : null);
    return [get('y'), get('m'), get('d')];
  }

  // yearfirst and dayfirst are False with pycti
  resolve(): [number | null, number | null, number | null] {
    const self = this.values;
    const length = self.length;
    const strids = new Map<string, number>();
    if (this.ystridx !== null) strids.set('y', this.ystridx);
    if (this.mstridx !== null) strids.set('m', this.mstridx);
    if (this.dstridx !== null) strids.set('d', this.dstridx);
    if ((length === strids.size && length > 0) || (length === 3 && strids.size === 2)) {
      return this.resolveFromStridxs(strids);
    }
    const { mstridx } = this;
    let year: number | null = null;
    let month: number | null = null;
    let day: number | null = null;
    if (length > 3) {
      fail('More than three YMD values');
    } else if (length === 1 || (mstridx !== null && length === 2)) {
      let other: number;
      if (mstridx !== null) {
        month = self[mstridx];
        other = at(self, mstridx - 1);
      } else {
        [other] = self;
      }
      if (length > 1 || mstridx === null) {
        if (other > 31) {
          year = other;
        } else {
          day = other;
        }
      }
    } else if (length === 2) {
      if (self[0] > 31) {
        [year, month] = self;
      } else if (self[1] > 31) {
        [month, year] = self;
      } else {
        [month, day] = self;
      }
    } else if (length === 3) {
      if (mstridx === 0) {
        if (self[1] > 31) {
          [month, year, day] = self;
        } else {
          [month, day, year] = self;
        }
      } else if (mstridx === 1) {
        if (self[0] > 31) {
          [year, month, day] = self;
        } else {
          [day, month, year] = self;
        }
      } else if (mstridx === 2) {
        if (self[1] > 31) {
          [day, year, month] = self;
        } else {
          [year, day, month] = self;
        }
      } else if (self[0] > 31 || this.ystridx === 0) {
        [year, month, day] = self;
      } else if (self[0] > 12) {
        [day, month, year] = self;
      } else {
        [month, day, year] = self;
      }
    }
    return [year, month, day];
  }
}

const isLeap = (year: number) => year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
const daysInMonth = (year: number, month: number) => {
  if (month < 1 || month > 12) {
    return fail('bad month number');
  }
  return [31, isLeap(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
};

const findHmsIdx = (idx: number, tokens: string[]) => {
  const length = tokens.length;
  if (idx + 1 < length && lookup(HMS, tokens[idx + 1]) !== null) {
    return idx + 1;
  }
  if (idx + 2 < length && tokens[idx + 1] === ' ' && lookup(HMS, tokens[idx + 2]) !== null) {
    return idx + 2;
  }
  if (idx > 0 && lookup(HMS, tokens[idx - 1]) !== null) {
    return idx - 1;
  }
  if (idx > 1 && idx === length - 1 && tokens[idx - 1] === ' ' && lookup(HMS, tokens[idx - 2]) !== null) {
    return idx - 2;
  }
  return null;
};

const parsems = (value: string): [number, number] => {
  if (!value.includes('.')) {
    return [pyInt(value), 0];
  }
  const parts = value.split('.');
  if (parts.length !== 2) {
    return fail('too many values to unpack');
  }
  return [pyInt(parts[0]), pyInt(parts[1].padEnd(6, '0').slice(0, 6))];
};

const parseMinSec = (value: Decimal): [number, number | null] => [value.integer, hasFraction(value) ? sixtiethsOf(value) : null];

const adjustAmpm = (hour: number, ampm: number) => {
  if (hour < 12 && ampm === 1) {
    return hour + 12;
  }
  if (hour === 12 && ampm === 0) {
    return 0;
  }
  return hour;
};

const couldBeTzname = (hour: number | null, tzname: string | null, tzoffset: number | null, token: string) => hour !== null
  && tzname === null
  && tzoffset === null
  && Array.from(token).length <= 5
  && (/^[A-Z]*$/.test(token) || UTCZONE.includes(token));

const parseNumericToken = (tokens: string[], startIdx: number, ymd: Ymd, res: ParseResult) => {
  let idx = startIdx;
  const valueRepr = tokens[idx];
  let value = toDecimal(valueRepr);
  const lenLi = valueRepr.length;
  const lenL = tokens.length;
  if (ymd.length === 3 && (lenLi === 2 || lenLi === 4) && res.hour === null
    && (idx + 1 >= lenL || (tokens[idx + 1] !== ':' && lookup(HMS, tokens[idx + 1]) === null))) {
    const s = tokens[idx];
    res.hour = pyInt(s.slice(0, 2));
    if (lenLi === 4) {
      res.minute = pyInt(s.slice(2));
    }
  } else if (lenLi === 6 || (lenLi > 6 && tokens[idx].indexOf('.') === 6)) {
    const s = tokens[idx];
    if (ymd.length === 0 && !tokens[idx].includes('.')) {
      ymd.append(s.slice(0, 2));
      ymd.append(s.slice(2, 4));
      ymd.append(s.slice(4));
    } else {
      res.hour = pyInt(s.slice(0, 2));
      res.minute = pyInt(s.slice(2, 4));
      [res.second, res.microsecond] = parsems(s.slice(4));
    }
  } else if (lenLi === 8 || lenLi === 12 || lenLi === 14) {
    const s = tokens[idx];
    ymd.append(s.slice(0, 4), 'Y');
    ymd.append(s.slice(4, 6));
    ymd.append(s.slice(6, 8));
    if (lenLi > 8) {
      res.hour = pyInt(s.slice(8, 10));
      res.minute = pyInt(s.slice(10, 12));
      if (lenLi > 12) {
        res.second = pyInt(s.slice(12));
      }
    }
  } else if (findHmsIdx(idx, tokens) !== null) {
    const hmsIdx = findHmsIdx(idx, tokens) as number;
    let hms: number;
    if (hmsIdx > idx) {
      hms = lookup(HMS, tokens[hmsIdx]) as number;
      idx = hmsIdx;
    } else {
      hms = (lookup(HMS, tokens[hmsIdx]) as number) + 1;
    }
    // dateutil _assign_hms
    if (hms === 0) {
      res.hour = value.integer;
      if (hasFraction(value)) {
        res.minute = sixtiethsOf(value);
      }
    } else if (hms === 1) {
      [res.minute, res.second] = parseMinSec(value);
    } else if (hms === 2) {
      [res.second, res.microsecond] = parsems(valueRepr);
    }
  } else if (idx + 2 < lenL && tokens[idx + 1] === ':') {
    res.hour = value.integer;
    value = toDecimal(tokens[idx + 2]);
    [res.minute, res.second] = parseMinSec(value);
    if (idx + 4 < lenL && tokens[idx + 3] === ':') {
      [res.second, res.microsecond] = parsems(tokens[idx + 4]);
      idx += 2;
    }
    idx += 2;
  } else if (idx + 1 < lenL && ['-', '/', '.'].includes(tokens[idx + 1])) {
    const sep = tokens[idx + 1];
    ymd.append(valueRepr);
    if (idx + 2 < lenL && !isJump(tokens[idx + 2])) {
      if (isDigitString(tokens[idx + 2])) {
        ymd.append(tokens[idx + 2]);
      } else {
        const month = lookup(MONTHS, tokens[idx + 2]);
        if (month !== null) {
          ymd.append(month, 'M');
        } else {
          fail('ValueError');
        }
      }
      if (idx + 3 < lenL && tokens[idx + 3] === sep) {
        const month = lookup(MONTHS, at(tokens, idx + 4));
        if (month !== null) {
          ymd.append(month, 'M');
        } else {
          ymd.append(tokens[idx + 4]);
        }
        idx += 2;
      }
      idx += 1;
    }
    idx += 1;
  } else if (idx + 1 >= lenL || isJump(tokens[idx + 1])) {
    if (idx + 2 < lenL && lookup(AMPM, tokens[idx + 2]) !== null) {
      res.hour = adjustAmpm(value.integer, lookup(AMPM, tokens[idx + 2]) as number);
      idx += 1;
    } else {
      ymd.append(value);
    }
    idx += 1;
  } else if (lookup(AMPM, tokens[idx + 1]) !== null && value.value >= 0 && value.value < 24) {
    res.hour = adjustAmpm(value.integer, lookup(AMPM, tokens[idx + 1]) as number);
    idx += 1;
  } else if (ymd.couldBeDay(value.value)) {
    ymd.append(value);
  } else {
    fail('ValueError');
  }
  return idx;
};

// dateutil parserinfo.convertyear: two-digit years around the current local year of the host
const convertYear = (year: number, centurySpecified: boolean) => {
  const currentYear = new Date().getFullYear();
  const century = Math.floor(currentYear / 100) * 100;
  let converted = year;
  if (converted < 100 && !centurySpecified) {
    converted += century;
    if (converted >= currentYear + 50) {
      converted -= 100;
    } else if (converted < currentYear - 50) {
      converted += 100;
    }
  }
  return converted;
};

// dateutil parser._parse (fuzzy False, dayfirst False, yearfirst False) and parserinfo.validate
const parseTokens = (timestr: string): ParseResult => {
  const res: ParseResult = {
    year: null, month: null, day: null, weekday: null, hour: null, minute: null, second: null, microsecond: null, tzname: null, tzoffset: null, ampm: null, centurySpecified: false,
  };
  const l = timelexSplit(timestr);
  const ymd = new Ymd();
  const lenL = l.length;
  let i = 0;
  while (i < lenL) {
    const valueRepr = l[i];
    if (isFloat(valueRepr)) {
      i = parseNumericToken(l, i, ymd, res);
    } else if (lookup(WEEKDAYS, l[i]) !== null) {
      res.weekday = lookup(WEEKDAYS, l[i]);
    } else if (lookup(MONTHS, l[i]) !== null) {
      ymd.append(lookup(MONTHS, l[i]) as number, 'M');
      if (i + 1 < lenL) {
        if (l[i + 1] === '-' || l[i + 1] === '/') {
          const sep = l[i + 1];
          ymd.append(at(l, i + 2));
          if (i + 3 < lenL && l[i + 3] === sep) {
            ymd.append(at(l, i + 4));
            i += 2;
          }
          i += 2;
        } else if (i + 4 < lenL && l[i + 1] === ' ' && l[i + 3] === ' ' && isPertain(l[i + 2])) {
          if (isDigitString(l[i + 4])) {
            ymd.append(String(convertYear(pyInt(l[i + 4]), false)), 'Y');
          }
          i += 4;
        }
      }
    } else if (lookup(AMPM, l[i]) !== null) {
      const value = lookup(AMPM, l[i]) as number;
      if (res.hour === null) {
        fail('No hour specified with AM or PM flag.');
      } else if (res.hour < 0 || res.hour > 12) {
        fail('Invalid hour specified for 12-hour clock.');
      }
      res.hour = adjustAmpm(res.hour as number, value);
      res.ampm = value;
    } else if (couldBeTzname(res.hour, res.tzname, res.tzoffset, l[i])) {
      res.tzname = l[i];
      res.tzoffset = infoTzOffset(res.tzname);
      if (i + 1 < lenL && (l[i + 1] === '+' || l[i + 1] === '-')) {
        // dateutil reads GMT+3 as the POSIX zone, 3 hours behind
        l[i + 1] = l[i + 1] === '+' ? '-' : '+';
        res.tzoffset = null;
        if (isUtcZone(res.tzname)) {
          res.tzname = null;
        }
      }
    } else if (res.hour !== null && (l[i] === '+' || l[i] === '-')) {
      const signal = l[i] === '+' ? 1 : -1;
      const lenLi = at(l, i + 1).length;
      let hourOffset: number;
      let minOffset: number;
      if (lenLi === 4) {
        hourOffset = pyInt(l[i + 1].slice(0, 2));
        minOffset = pyInt(l[i + 1].slice(2));
      } else if (i + 2 < lenL && l[i + 2] === ':') {
        hourOffset = pyInt(l[i + 1]);
        minOffset = pyInt(at(l, i + 3));
        i += 2;
      } else if (lenLi <= 2) {
        hourOffset = pyInt(l[i + 1].slice(0, 2));
        minOffset = 0;
      } else {
        return fail(timestr);
      }
      res.tzoffset = signal * (hourOffset * 3600 + minOffset * 60);
      if (i + 5 < lenL && isJump(l[i + 2]) && l[i + 3] === '(' && l[i + 5] === ')' && Array.from(l[i + 4]).length >= 3
        && couldBeTzname(res.hour, res.tzname, null, l[i + 4])) {
        res.tzname = l[i + 4];
        i += 4;
      }
      i += 1;
    } else if (!isJump(l[i])) {
      fail(timestr);
    }
    i += 1;
  }
  [res.year, res.month, res.day] = ymd.resolve();
  res.centurySpecified = ymd.centurySpecified;
  // parserinfo.validate
  if (res.year !== null) {
    res.year = convertYear(res.year, res.centurySpecified);
  }
  if ((res.tzoffset === 0 && !res.tzname) || res.tzname === 'Z' || res.tzname === 'z') {
    res.tzname = 'UTC';
    res.tzoffset = 0;
  } else if (res.tzoffset !== 0 && res.tzname && isUtcZone(res.tzname)) {
    res.tzoffset = 0;
  }
  return res;
};

interface ParsedDate {
  // UTC milliseconds of the naive date (microseconds below the millisecond in `microsecond`)
  naive: Date;
  microsecond: number;
  // Offset in seconds, null for a naive date
  offset: number | null;
}

// dateutil parser.parse(timestr, default=1970-01-01T00:00:00): _build_naive and _build_tzaware
const parseDate = (timestr: string): ParsedDate => {
  const res = parseTokens(asciiDigits(timestr));
  const attributes: (keyof ParseResult)[] = ['year', 'month', 'day', 'weekday', 'hour', 'minute', 'second', 'microsecond', 'tzname', 'tzoffset', 'ampm'];
  if (attributes.every((attribute) => res[attribute] === null)) {
    fail(`String does not contain a date: ${timestr}`);
  }
  const year = res.year ?? EPOCH_YEAR;
  const month = res.month ?? 1;
  if (res.day === null) {
    daysInMonth(year, month);
  }
  const day = res.day ?? 1;
  const hour = res.hour ?? 0;
  const minute = res.minute ?? 0;
  const second = res.second ?? 0;
  const microsecond = res.microsecond ?? 0;
  if (year < 1 || year > 9999) {
    fail(`year ${year} is out of range`);
  }
  if (month < 1 || month > 12) {
    fail('month must be in 1..12');
  }
  if (day < 1 || day > daysInMonth(year, month)) {
    fail('day is out of range for month');
  }
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59 || microsecond < 0 || microsecond > 999999) {
    fail('time is out of range');
  }
  const naive = new Date(Date.UTC(2000, month - 1, day, hour, minute, second, Math.floor(microsecond / 1000)));
  naive.setUTCFullYear(year);
  if (res.weekday !== null && !res.day) {
    // relativedelta(weekday=...): the next such weekday, the same day included
    const current = (naive.getUTCDay() + 6) % 7;
    naive.setUTCDate(naive.getUTCDate() + ((7 - current + res.weekday) % 7));
    if (naive.getUTCFullYear() > 9999) {
      fail('date value out of range');
    }
  }
  let offset: number | null;
  if (res.tzname && LOCAL_TZ_NAMES.includes(res.tzname)) {
    offset = 0;
  } else if (res.tzoffset === 0) {
    offset = 0;
  } else if (res.tzoffset) {
    offset = res.tzoffset;
  } else {
    // No zone, or a name dateutil does not know (UnknownTimezoneWarning): naive
    offset = null;
  }
  return { naive, microsecond: microsecond % 1000, offset };
};

const pad = (value: number, length = 2) => String(value).padStart(length, '0');

// pycti opencti_stix2_utils.py:guess_past_date
export const guessPastDate = (text: unknown, now: Date = new Date()): string | null => {
  if (typeof text !== 'string' || text.length === 0) {
    return null;
  }
  const yesterday = now.getTime() - 24 * 3600 * 1000;
  for (const candidate of dateCandidates(text)) {
    let parsed: ParsedDate;
    try {
      parsed = parseDate(candidate);
    } catch (error) {
      if (!(error instanceof ParseError)) {
        throw error;
      }
      // The first candidate dateutil rejects ends the search (see above)
      return null;
    }
    // pycti _to_naive_utc
    const match = new Date(parsed.naive.getTime());
    if (parsed.offset !== null) {
      if (Math.abs(parsed.offset) >= 24 * 3600) {
        // utcoffset out of range: ValueError
        return null;
      }
      match.setTime(match.getTime() - parsed.offset * 1000);
      if (match.getUTCFullYear() < 1 || match.getUTCFullYear() > 9999) {
        // OverflowError
        return null;
      }
    }
    const year = match.getUTCFullYear();
    if (match.getTime() < yesterday && year >= 1000 && year <= 9999) {
      return `${pad(year, 4)}-${pad(match.getUTCMonth() + 1)}-${pad(match.getUTCDate())}T${pad(match.getUTCHours())}:${pad(match.getUTCMinutes())}:${pad(match.getUTCSeconds())}Z`;
    }
  }
  return null;
};
