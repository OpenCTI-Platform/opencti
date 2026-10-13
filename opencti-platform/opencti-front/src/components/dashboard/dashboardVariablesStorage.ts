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
  if (Object.keys(values).length === 0) {
    window.localStorage.removeItem(key);
  } else {
    window.localStorage.setItem(key, JSON.stringify(values));
  }
};
