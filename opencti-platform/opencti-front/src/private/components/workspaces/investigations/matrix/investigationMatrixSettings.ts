import { useCallback, useEffect, useState } from 'react';
import type { EntityOption } from '@components/common/form/EntitySelect';
import { DEFAULT_MATRIX_FILTERS, hasActiveMatrixFilters, type InvestigationMatrixFilters, MATRIX_RELATIONSHIP_TYPES, type MatrixRelationshipType } from './matrixFilters';

/**
 * What the user chose in the matrix toolbar. The matrix unmounts when the graph view is shown,
 * so these settings are held by the investigation graph, which stays mounted, and survive a view switch.
 */
export interface InvestigationMatrixSettings {
  // Undefined until the user picks one: the matrix then shows the default kill chain.
  killChain?: string;
  onlyUsed: boolean;
  heatmap: boolean;
  securityPlatforms: EntityOption[];
}

export type InvestigationMatrixSettingsChange = (change: Partial<InvestigationMatrixSettings>) => void;

export const DEFAULT_INVESTIGATION_MATRIX_SETTINGS: InvestigationMatrixSettings = {
  killChain: undefined,
  onlyUsed: false,
  heatmap: false,
  securityPlatforms: [],
};

/**
 * The matrix settings of one investigation. The investigation graph is mounted again for each investigation
 * (keyed by its id); the id check also keeps the kill chain, heatmap and security platforms of one investigation
 * away from another if it ever is not.
 */
export const useInvestigationMatrixSettings = (
  investigationId: string,
): [InvestigationMatrixSettings, InvestigationMatrixSettingsChange] => {
  const [state, setState] = useState({ investigationId, settings: DEFAULT_INVESTIGATION_MATRIX_SETTINGS });
  const settings = state.investigationId === investigationId ? state.settings : DEFAULT_INVESTIGATION_MATRIX_SETTINGS;
  const change = useCallback<InvestigationMatrixSettingsChange>((update) => setState((current) => ({
    investigationId,
    settings: { ...(current.investigationId === investigationId ? current.settings : DEFAULT_INVESTIGATION_MATRIX_SETTINGS), ...update },
  })), [investigationId]);
  return [settings, change];
};

export const matrixFiltersStorageKey = (investigationId: string) => `investigation-matrix-filters-${investigationId}`;

const isRelationshipType = (value: string): value is MatrixRelationshipType => {
  return (MATRIX_RELATIONSHIP_TYPES as string[]).includes(value);
};

// Anything that is not an array falls back to the default; non-string items are dropped.
const stringsOf = (value: unknown): string[] => {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
};

// Two valid ISO dates, start before end, or nothing: a range with one bad end must not apply its other end.
const timeRangeOf = (value: unknown): [string, string] | undefined => {
  if (!Array.isArray(value) || value.length !== 2) return undefined;
  const [start, end] = value;
  if (typeof start !== 'string' || typeof end !== 'string') return undefined;
  const startTime = new Date(start).getTime();
  const endTime = new Date(end).getTime();
  if (Number.isNaN(startTime) || Number.isNaN(endTime) || startTime > endTime) return undefined;
  return [start, end];
};

/** Parsed and checked stored filters; defaults for anything missing or malformed. */
export const readMatrixFilters = (investigationId: string): InvestigationMatrixFilters => {
  try {
    const stored: unknown = JSON.parse(localStorage.getItem(matrixFiltersStorageKey(investigationId)) ?? 'null');
    if (typeof stored !== 'object' || stored === null || Array.isArray(stored)) return DEFAULT_MATRIX_FILTERS;
    const record = stored as Record<string, unknown>;
    const timeRange = timeRangeOf(record.timeRange);
    return {
      disabledEntityTypes: stringsOf(record.disabledEntityTypes),
      disabledRelationshipTypes: stringsOf(record.disabledRelationshipTypes).filter(isRelationshipType),
      disabledMarkings: stringsOf(record.disabledMarkings),
      disabledCreators: stringsOf(record.disabledCreators),
      ...(timeRange ? { timeRange } : {}),
    };
  } catch {
    // Unreadable or unparsable storage: start from the defaults.
    return DEFAULT_MATRIX_FILTERS;
  }
};

// Storage can be full or blocked: the filters then work for this session only.
const writeMatrixFilters = (investigationId: string, filters: InvestigationMatrixFilters | undefined) => {
  try {
    if (filters) localStorage.setItem(matrixFiltersStorageKey(investigationId), JSON.stringify(filters));
    else localStorage.removeItem(matrixFiltersStorageKey(investigationId));
  } catch {
    // Not persisted.
  }
};

/**
 * The matrix filters of one investigation, kept in local storage: they survive a reload. The investigation
 * graph is mounted again for each investigation (keyed by its id), so the hook reads the storage once.
 */
export const useInvestigationMatrixFilters = (
  investigationId: string,
): [InvestigationMatrixFilters, (change: Partial<InvestigationMatrixFilters>) => void, () => void] => {
  // The id the filters were read for: they are only ever written back under it.
  const [{ id, filters }, setState] = useState(() => ({ id: investigationId, filters: readMatrixFilters(investigationId) }));
  useEffect(() => {
    // No filter in use: nothing stored, so that a cleared investigation leaves no entry behind.
    writeMatrixFilters(id, hasActiveMatrixFilters(filters) ? filters : undefined);
  }, [id, filters]);
  const change = useCallback((update: Partial<InvestigationMatrixFilters>) => {
    setState((current) => ({ ...current, filters: { ...current.filters, ...update } }));
  }, []);
  const clear = useCallback(() => setState((current) => ({ ...current, filters: DEFAULT_MATRIX_FILTERS })), []);
  return [filters, change, clear];
};
