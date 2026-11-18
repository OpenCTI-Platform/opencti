// The password and the sensitive query parameters of a feed URI: blanked in a bundle, asked again at import
const SENSITIVE_PARAMETER_NAME = /authorization|token|key|secret|password|cookie|credential/i;

export const URI_PASSWORD_CREDENTIAL_KEY = 'uri:password';
const URI_PARAMETER_CREDENTIAL_PREFIX = 'uri:query:';
export const uriParameterCredentialKey = (name: string) => `${URI_PARAMETER_CREDENTIAL_PREFIX}${name}`;

const parseUri = (uri: string) => {
  try {
    return new URL(uri);
  } catch {
    return undefined;
  }
};

const sensitiveParameterNames = (url: URL) => [...new Set([...url.searchParams.keys()].filter((name) => SENSITIVE_PARAMETER_NAME.test(name)))];

export const sanitizeExportedUri = (uri: string) => {
  const url = parseUri(uri);
  if (!url) {
    return uri;
  }
  const parameters = sensitiveParameterNames(url).filter((name) => url.searchParams.getAll(name).some((value) => value !== ''));
  if (!url.password && parameters.length === 0) {
    return uri;
  }
  url.password = '';
  parameters.forEach((name) => url.searchParams.set(name, ''));
  return url.toString();
};

export const uriCredentials = (bundleUri: string, targetUri?: string) => {
  const url = parseUri(bundleUri);
  if (!url) {
    return [];
  }
  const target = targetUri ? parseUri(targetUri) : undefined;
  const password = url.username && !url.password
    ? [{ key: URI_PASSWORD_CREDENTIAL_KEY, description: 'Password of the user of the URI', stored: target?.username === url.username ? decodeURIComponent(target.password) : '' }]
    : [];
  const parameters = sensitiveParameterNames(url)
    .filter((name) => url.searchParams.get(name) === '')
    .map((name) => ({ key: uriParameterCredentialKey(name), description: `Value of the URI parameter ${name}`, stored: target?.searchParams.get(name) ?? '' }));
  return [...password, ...parameters];
};

export const uriWithCredentials = (bundleUri: string, values: Record<string, string>) => {
  const url = parseUri(bundleUri);
  if (!url || Object.values(values).every((value) => value === '')) {
    return bundleUri;
  }
  Object.entries(values).forEach(([key, value]) => {
    if (key === URI_PASSWORD_CREDENTIAL_KEY) {
      url.password = encodeURIComponent(value);
    } else {
      url.searchParams.set(key.slice(URI_PARAMETER_CREDENTIAL_PREFIX.length), value);
    }
  });
  return url.toString();
};

// Same scheme, host and port: the stored credentials of a feed are only kept for its own server
export const isSameUriDestination = (left?: string | null, right?: string | null) => {
  const a = left ? parseUri(left) : undefined;
  const b = right ? parseUri(right) : undefined;
  return !!a && !!b && a.protocol === b.protocol && a.hostname === b.hostname && a.port === b.port;
};
