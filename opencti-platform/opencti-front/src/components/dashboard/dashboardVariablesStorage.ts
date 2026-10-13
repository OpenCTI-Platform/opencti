export const dashboardVariablesStorageKey = (userId: string, workspaceId: string) => `dashboard-variables-${userId}-${workspaceId}`;

export const readStoredVariableValues = (key: string): Record<string, string> => {
  try {
    const raw = window.localStorage.getItem(key);
    const parsed: unknown = raw ? JSON.parse(raw) : {};
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return Object.fromEntries(Object.entries(parsed).filter(([, value]) => typeof value === 'string' && value !== '')) as Record<string, string>;
  } catch {
    return {};
  }
};

export const writeStoredVariableValues = (key: string, values: Record<string, string>) => {
  try {
    if (Object.keys(values).length === 0) {
      window.localStorage.removeItem(key);
    } else {
      window.localStorage.setItem(key, JSON.stringify(values));
    }
  } catch {
    // Storage full or denied: the values stay in memory for the session, they are just not persisted.
  }
};

export const serializeVariablesParam = (values: Record<string, string>) => (
  Object.entries(values).map(([id, value]) => `${id}:${encodeURIComponent(value)}`).join(',')
);

export const parseVariablesParam = (search: string): Record<string, string> => {
  const raw = new URLSearchParams(search).get('variables');
  if (!raw) return {};
  const result: Record<string, string> = {};
  raw.split(',').forEach((pair) => {
    const separator = pair.indexOf(':');
    if (separator <= 0) return;
    try {
      const value = decodeURIComponent(pair.slice(separator + 1));
      if (value) result[pair.slice(0, separator)] = value;
    } catch { /* paramètre mal formé : ignoré */ }
  });
  return result;
};

export const writeVariablesParam = (values: Record<string, string>) => {
  const url = new URL(window.location.href);
  if (Object.keys(values).length === 0) url.searchParams.delete('variables');
  else url.searchParams.set('variables', serializeVariablesParam(values));
  try {
    window.history.replaceState(window.history.state, '', url);
  } catch {
    // Browsers rate-limit history updates (SecurityError): the URL then lags behind, the state is not affected.
  }
};
