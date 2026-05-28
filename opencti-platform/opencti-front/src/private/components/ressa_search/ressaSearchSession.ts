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
    return JSON.parse(raw) as RessaSearchSessionState;
  } catch {
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
