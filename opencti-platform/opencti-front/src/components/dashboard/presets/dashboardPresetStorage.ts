export const PRESET_PARAM = 'preset';

export const dashboardPresetStorageKey = (userId: string, workspaceId: string) => `dashboard-preset-${userId}-${workspaceId}`;

export const readStoredPresetId = (key: string): string | null => {
  try {
    const raw = window.localStorage.getItem(key);
    return raw && raw !== '' ? raw : null;
  } catch {
    return null;
  }
};

export const writeStoredPresetId = (key: string, presetId: string | null) => {
  try {
    if (presetId === null) {
      window.localStorage.removeItem(key);
    } else {
      window.localStorage.setItem(key, presetId);
    }
  } catch {
    // Storage full or denied: the preset stays selected for the session, it is just not persisted.
  }
};

export const parsePresetParam = (search: string): string | null => {
  const raw = new URLSearchParams(search).get(PRESET_PARAM);
  return raw && raw !== '' ? raw : null;
};

export const writePresetParam = (presetId: string | null) => {
  const url = new URL(window.location.href);
  if (presetId === null) url.searchParams.delete(PRESET_PARAM);
  else url.searchParams.set(PRESET_PARAM, presetId);
  try {
    window.history.replaceState(window.history.state, '', url);
  } catch {
    // Browsers rate-limit history updates (SecurityError): the URL then lags behind, the state is not affected.
  }
};
