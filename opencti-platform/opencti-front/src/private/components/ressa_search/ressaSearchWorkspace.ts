import { v4 as uuid } from 'uuid';

const WORKSPACE_STORAGE_KEY = 'ressa-search-workspace';

export interface SearchTab {
  id: string;
  query: string;
  pinned?: boolean;
}

export interface SearchWorkspace {
  activeTabId: string;
  tabs: SearchTab[];
}

export const createEmptyTab = (): SearchTab => ({
  id: uuid(),
  query: '',
});

export const createTabWithQuery = (query: string): SearchTab => ({
  id: uuid(),
  query,
});

export const createDefaultWorkspace = (): SearchWorkspace => {
  const tab = createEmptyTab();
  return {
    activeTabId: tab.id,
    tabs: [tab],
  };
};

const isRecord = (value: unknown): value is Record<string, unknown> => (
  typeof value === 'object' && value !== null && !Array.isArray(value)
);

const normalizeTab = (tab: unknown): SearchTab => {
  if (!isRecord(tab)) {
    return createEmptyTab();
  }

  const id = typeof tab.id === 'string' && tab.id.length > 0 ? tab.id : uuid();
  const query = typeof tab.query === 'string' ? tab.query : '';
  const pinned = tab.pinned === true ? true : undefined;

  return pinned ? { id, query, pinned } : { id, query };
};

const dedupeTabsById = (tabs: SearchTab[]): SearchTab[] => {
  const seen = new Set<string>();
  return tabs.filter((tab) => {
    if (seen.has(tab.id)) return false;
    seen.add(tab.id);
    return true;
  });
};

export const sortWorkspaceTabs = (tabs: SearchTab[]): SearchTab[] => {
  const pinned = tabs.filter((tab) => tab.pinned);
  const unpinned = tabs.filter((tab) => !tab.pinned);
  return [...pinned, ...unpinned];
};

export const normalizeWorkspace = (data: unknown): SearchWorkspace => {
  if (!isRecord(data)) {
    return createDefaultWorkspace();
  }

  let tabs: SearchTab[] = [];
  if (Array.isArray(data.tabs)) {
    tabs = dedupeTabsById(data.tabs.map(normalizeTab));
  }

  if (tabs.length === 0) {
    return createDefaultWorkspace();
  }

  tabs = sortWorkspaceTabs(tabs);

  const activeTabId = typeof data.activeTabId === 'string'
    && tabs.some((tab) => tab.id === data.activeTabId)
    ? data.activeTabId
    : tabs[0].id;

  return { activeTabId, tabs };
};

export const getActiveTab = (workspace: SearchWorkspace): SearchTab => {
  const normalized = normalizeWorkspace(workspace);
  const activeTab = normalized.tabs.find((tab) => tab.id === normalized.activeTabId);
  return activeTab ?? normalized.tabs[0];
};

export const findTabByQuery = (workspace: SearchWorkspace, query: string): SearchTab | undefined => {
  const trimmed = query.trim();
  if (!trimmed) return undefined;

  const normalized = normalizeWorkspace(workspace);
  return normalized.tabs.find((tab) => tab.query.trim() === trimmed);
};

export const applyInitialUrlQuery = (workspace: SearchWorkspace, query: string): SearchWorkspace => {
  const trimmed = query.trim();
  if (!trimmed) {
    return normalizeWorkspace(workspace);
  }

  const normalized = normalizeWorkspace(workspace);
  const existingTab = findTabByQuery(normalized, trimmed);
  if (existingTab) {
    return normalizeWorkspace({
      ...normalized,
      activeTabId: existingTab.id,
    });
  }

  const tab = createTabWithQuery(trimmed);
  return normalizeWorkspace({
    activeTabId: tab.id,
    tabs: [...normalized.tabs, tab],
  });
};

export const clearWorkspaceStorage = (): void => {
  try {
    localStorage.removeItem(WORKSPACE_STORAGE_KEY);
  } catch {
    // Ignore private mode or access errors
  }
};

export const saveWorkspace = (workspace: SearchWorkspace) => {
  const normalized = normalizeWorkspace(workspace);
  try {
    localStorage.setItem(WORKSPACE_STORAGE_KEY, JSON.stringify(normalized));
  } catch {
    // Ignore quota or private mode errors
  }
};

export const loadWorkspace = (): SearchWorkspace => {
  try {
    const raw = localStorage.getItem(WORKSPACE_STORAGE_KEY);
    if (!raw) {
      return createDefaultWorkspace();
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      clearWorkspaceStorage();
      return createDefaultWorkspace();
    }

    const normalized = normalizeWorkspace(parsed);
    saveWorkspace(normalized);
    return normalized;
  } catch {
    clearWorkspaceStorage();
    return createDefaultWorkspace();
  }
};
