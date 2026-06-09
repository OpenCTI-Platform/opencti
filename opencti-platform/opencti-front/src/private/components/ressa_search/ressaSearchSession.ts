import type { FilterGroup } from './FilterSidebar';
import type { RawQueryResponse } from './mockRessaSearchApi';

const SESSION_STORAGE_KEY = 'ressa-search-session-state';

export const RESSA_SEARCH_QUERY_PARAM = 'q';

export interface RessaSearchSessionState {
  searchValue: string;
  rawResponse: RawQueryResponse;
  extractedFilters: FilterGroup[];
  page: number;
  rowsPerPage: number;
}

const isRecord = (value: unknown): value is Record<string, unknown> => (
  typeof value === 'object' && value !== null && !Array.isArray(value)
);

const isValidSessionState = (value: unknown): value is RessaSearchSessionState => {
  if (!isRecord(value)) return false;
  if (typeof value.searchValue !== 'string') return false;
  if (typeof value.page !== 'number' || !Number.isFinite(value.page)) return false;
  if (typeof value.rowsPerPage !== 'number' || !Number.isFinite(value.rowsPerPage)) return false;
  if (!Array.isArray(value.extractedFilters)) return false;
  if (!isRecord(value.rawResponse)) return false;
  return true;
};

export const saveRessaSearchSession = (state: RessaSearchSessionState) => {
  try {
    sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Ignore quota or private mode errors
  }
};

export const loadRessaSearchSession = (): RessaSearchSessionState | null => {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      clearRessaSearchSession();
      return null;
    }

    if (!isValidSessionState(parsed)) {
      clearRessaSearchSession();
      return null;
    }

    return parsed;
  } catch {
    clearRessaSearchSession();
    return null;
  }
};

export const clearRessaSearchSession = () => {
  try {
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
  } catch {
    // Ignore
  }
};
