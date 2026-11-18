// The password and the sensitive query parameters of a feed URI: blanked in a bundle, asked again at import.
// The URI is edited as written, never re-serialised: the rest of it (encoding, $variables, repeated or bare parameters) is kept as is
const SENSITIVE_WORDS = new Set([
  'authorization', 'auth', 'token', 'secret', 'password', 'passwd', 'pwd', 'cookie', 'credential',
  'apikey', 'accesskey', 'secretkey', 'privatekey', 'accesstoken', 'sessionid',
]);

const nameWords = (name: string) => name
  .replace(/([a-z\d])([A-Z])/g, '$1 $2')
  .split(/[\s_.-]+/)
  .filter((word) => word !== '')
  .map((word) => word.toLowerCase());

const isSensitiveWord = (word: string) => SENSITIVE_WORDS.has(word) || SENSITIVE_WORDS.has(word.replace(/s$/, ''));

// The words of the name are compared, not substrings: `api_key`, `apiKey`, `access-token` and a bare `key` are sensitive, `sort_key`, `keyword` and `monkey` are not
export const isSensitiveParameterName = (name: string) => {
  const words = nameWords(name);
  return (words.length === 1 && words[0] === 'key')
    || words.some(isSensitiveWord)
    || words.some((word, index) => index > 0 && isSensitiveWord(`${words[index - 1]}${word}`));
};

export const URI_PASSWORD_CREDENTIAL_KEY = 'uri:password';
const URI_PARAMETER_CREDENTIAL_PREFIX = 'uri:query:';
export const uriParameterCredentialKey = (name: string) => `${URI_PARAMETER_CREDENTIAL_PREFIX}${name}`;

const URI_PATTERN = /^([a-z][a-z\d+.-]*:\/\/)([^/?#]*)([^?#]*)(?:\?([^#]*))?(#.*)?$/i;

interface RawUri {
  scheme: string;
  userinfo?: string;
  host: string;
  path: string;
  query?: string;
  fragment?: string;
}

const parseRawUri = (uri: string): RawUri | undefined => {
  const match = uri.match(URI_PATTERN);
  if (!match) {
    return undefined;
  }
  const [, scheme, authority, path, query, fragment] = match;
  const at = authority.lastIndexOf('@');
  return { scheme, userinfo: at >= 0 ? authority.slice(0, at) : undefined, host: at >= 0 ? authority.slice(at + 1) : authority, path, query, fragment };
};

const formatRawUri = ({ scheme, userinfo, host, path, query, fragment }: RawUri) => {
  return `${scheme}${userinfo !== undefined ? `${userinfo}@` : ''}${host}${path}${query !== undefined ? `?${query}` : ''}${fragment ?? ''}`;
};

const decodeComponent = (value: string) => {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
};

interface QueryPair {
  raw: string;
  name: string;
  value?: string;
}

const queryPairs = (query: string): QueryPair[] => query.split('&').map((raw) => {
  const equal = raw.indexOf('=');
  return equal < 0 ? { raw, name: decodeComponent(raw) } : { raw, name: decodeComponent(raw.slice(0, equal)), value: raw.slice(equal + 1) };
});

const rawPassword = (userinfo?: string) => {
  const colon = userinfo?.indexOf(':') ?? -1;
  return userinfo !== undefined && colon >= 0 ? userinfo.slice(colon + 1) : undefined;
};

const withPassword = (userinfo: string, password: string) => `${userinfo.slice(0, userinfo.indexOf(':'))}:${password}`;

const withParameterValues = (query: string, values: (pair: QueryPair) => string | undefined) => {
  return queryPairs(query).map((pair) => {
    const value = values(pair);
    return value === undefined ? pair.raw : `${pair.raw.slice(0, pair.raw.indexOf('='))}=${value}`;
  }).join('&');
};

// The password keeps its separator (`user:@host`): an import tells a blanked password from a URI that has none (`TOKEN@host`)
export const sanitizeExportedUri = (uri: string) => {
  const raw = parseRawUri(uri);
  if (!raw) {
    return uri;
  }
  const password = rawPassword(raw.userinfo);
  const sanitized: RawUri = {
    ...raw,
    userinfo: raw.userinfo !== undefined && password ? withPassword(raw.userinfo, '') : raw.userinfo,
    query: raw.query !== undefined ? withParameterValues(raw.query, ({ name, value }) => (value && isSensitiveParameterName(name) ? '' : undefined)) : undefined,
  };
  return formatRawUri(sanitized);
};

// The blanked secrets of the bundle URI, with the raw value the target URI holds for each (empty when it holds none)
export const uriCredentials = (bundleUri: string, targetUri?: string) => {
  const raw = parseRawUri(bundleUri);
  if (!raw) {
    return [];
  }
  const target = targetUri ? parseRawUri(targetUri) : undefined;
  const targetPairs = target?.query !== undefined ? queryPairs(target.query) : [];
  const password = rawPassword(raw.userinfo) === ''
    ? [{ key: URI_PASSWORD_CREDENTIAL_KEY, description: 'Password of the user of the URI', stored: rawPassword(target?.userinfo) ?? '' }]
    : [];
  const parameters = raw.query === undefined ? [] : [...new Set(queryPairs(raw.query)
    .filter(({ name, value }) => value === '' && isSensitiveParameterName(name))
    .map(({ name }) => name))]
    .map((name) => ({
      key: uriParameterCredentialKey(name),
      description: `Value of the URI parameter ${name}`,
      stored: targetPairs.find((pair) => pair.name === name && pair.value)?.value ?? '',
    }));
  return [...password, ...parameters];
};

export const encodeUriCredential = (value: string) => encodeURIComponent(value);

// Fills the blanked secrets of the bundle URI with raw (already encoded) values; a secret without value stays blank
export const uriWithCredentials = (bundleUri: string, rawValues: Record<string, string>) => {
  const raw = parseRawUri(bundleUri);
  if (!raw || Object.values(rawValues).every((value) => value === '')) {
    return bundleUri;
  }
  const password = rawValues[URI_PASSWORD_CREDENTIAL_KEY];
  return formatRawUri({
    ...raw,
    userinfo: raw.userinfo !== undefined && password && rawPassword(raw.userinfo) === '' ? withPassword(raw.userinfo, password) : raw.userinfo,
    query: raw.query !== undefined
      ? withParameterValues(raw.query, ({ name, value }) => (value === '' && rawValues[uriParameterCredentialKey(name)] ? rawValues[uriParameterCredentialKey(name)] : undefined))
      : undefined,
  });
};

const parseUrl = (uri?: string | null) => {
  if (!uri) {
    return undefined;
  }
  const raw = parseRawUri(uri);
  // A $variable in the authority is replaced when the feed runs: its server is not known
  if (!raw || `${raw.userinfo ?? ''}@${raw.host}`.includes('$')) {
    return undefined;
  }
  try {
    return new URL(uri);
  } catch {
    return undefined;
  }
};

// Same scheme, host and port: the stored credentials of a feed are only kept for its own server
export const isSameUriDestination = (left?: string | null, right?: string | null) => {
  const a = parseUrl(left);
  const b = parseUrl(right);
  return !!a && !!b && a.protocol === b.protocol && a.hostname === b.hostname && a.port === b.port;
};

export const uriOrigin = (uri?: string | null) => {
  try {
    return uri ? new URL(uri).origin : undefined;
  } catch {
    return undefined;
  }
};
