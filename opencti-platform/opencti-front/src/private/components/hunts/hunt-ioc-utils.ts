/** A value of an indicator hunt typed as an observable, as the platform stores it. */
export interface HuntIocValueInput {
  observable_type: string;
  value: string;
}

export interface ParsedIocText {
  values: HuntIocValueInput[];
  /** Pieces of text that are no value an indicator hunt looks up */
  invalid: string[];
  /** Values pasted more than once */
  duplicates: number;
}

// The same rules as the platform (hunt-iocs.ts): a value the platform would refuse is flagged before saving
const IPV4_PATTERN = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const EMAIL_PATTERN = /^[^\s@]{1,64}@[a-z0-9.-]{1,253}$/;
const MAC_PATTERN = /^[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}$/;
const HEX_PATTERN = /^[0-9a-f]+$/;
const URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i;
const HASH_LENGTHS = [32, 40, 64, 128];
const VALUE_MAX_LENGTH = 2048;

const isIPv6 = (value: string) => {
  if (!value.includes(':') || !/^[0-9a-f:.]+$/i.test(value)) {
    return false;
  }
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
};

/** Undoes the usual defanging of shared indicators: hxxp, [.], (.), [:], [@]. */
export const refangIoc = (value: string) => value
  .trim()
  .replace(/^hxxp/i, 'http')
  .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
  .replace(/\[:\]/g, ':')
  .replace(/\[@\]|\(@\)/g, '@');

/** The value of a pasted text typed as the observable an indicator hunt looks up, null when it is none. */
export const detectIoc = (raw: string): HuntIocValueInput | null => {
  const value = refangIoc(raw);
  if (value.length === 0 || value.length > VALUE_MAX_LENGTH) {
    return null;
  }
  const lower = value.toLowerCase();
  if (IPV4_PATTERN.test(value)) return { observable_type: 'IPv4-Addr', value };
  if (isIPv6(value)) return { observable_type: 'IPv6-Addr', value: lower };
  if (URL_PATTERN.test(value)) return { observable_type: 'Url', value };
  if (EMAIL_PATTERN.test(lower)) return { observable_type: 'Email-Addr', value: lower };
  if (MAC_PATTERN.test(lower)) return { observable_type: 'Mac-Addr', value: lower.replace(/-/g, ':') };
  if (HEX_PATTERN.test(lower) && HASH_LENGTHS.includes(lower.length)) return { observable_type: 'StixFile', value: lower };
  const domain = lower.replace(/\.$/, '');
  if (DOMAIN_PATTERN.test(domain)) return { observable_type: 'Domain-Name', value: domain };
  return null;
};

/** The values of a pasted text: one per line, comma, semicolon or space, defanged values restored, duplicates removed. */
export const parseIocText = (text: string): ParsedIocText => {
  const pieces = (text ?? '').split(/[\s,;]+/).map((piece) => piece.trim()).filter((piece) => piece.length > 0);
  const byKey = new Map<string, HuntIocValueInput>();
  const invalid: string[] = [];
  let duplicates = 0;
  pieces.forEach((piece) => {
    const detected = detectIoc(piece);
    if (!detected) {
      invalid.push(piece);
      return;
    }
    const key = `${detected.observable_type}|${detected.value}`;
    if (byKey.has(key)) {
      duplicates += 1;
    } else {
      byKey.set(key, detected);
    }
  });
  return { values: Array.from(byKey.values()), invalid, duplicates };
};

/** The pasted values of a stored indicator hunt, one per line, as the paste field shows them. */
export const iocValuesToText = (values: ReadonlyArray<HuntIocValueInput> | null | undefined) => (values ?? []).map((item) => item.value).join('\n');

type Translate = (message: string, options?: { values: Record<string, string> }) => string;

/** Observable types an indicator hunt looks up, with the label the user interface gives them. */
export const iocTypeLabel = (observableType: string, t_i18n: Translate, hashAlgorithm?: string | null) => {
  switch (observableType) {
    case 'IPv4-Addr': return t_i18n('IPv4 address');
    case 'IPv6-Addr': return t_i18n('IPv6 address');
    case 'Domain-Name': return t_i18n('Domain name');
    case 'Hostname': return t_i18n('Hostname');
    case 'Url': return t_i18n('URL');
    case 'Email-Addr': return t_i18n('Email address');
    case 'Mac-Addr': return t_i18n('MAC address');
    case 'StixFile': return hashAlgorithm ? t_i18n('File hash ({algorithm})', { values: { algorithm: hashAlgorithm } }) : t_i18n('File hash');
    default: return observableType;
  }
};
