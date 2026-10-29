import type { DashboardConfig } from './dashboard-types';

export type DashboardDateField = 'startDate' | 'endDate' | 'relativeDate';

export interface DashboardTimeRange {
  startDate: string | null;
  endDate: string | null;
  relativeDate: string | null;
}

export const pickTimeRange = (config: DashboardConfig | undefined): DashboardTimeRange => ({
  startDate: config?.startDate ?? null,
  endDate: config?.endDate ?? null,
  relativeDate: config?.relativeDate ?? null,
});

/**
 * The range once one of its fields is changed from the time filters: `none` means no value, and a relative date
 * replaces the absolute ones. Any other key of `range` (a whole dashboard config) is kept as is.
 */
export const applyDateChange = <T extends Pick<DashboardConfig, DashboardDateField>>(range: T, type: DashboardDateField, value: string | null): T => {
  const next = { ...range, [type]: value === 'none' ? null : value };
  if (type === 'relativeDate' && value !== 'none') {
    return { ...next, startDate: null, endDate: null };
  }
  return next;
};

export const isSameTimeRange = (a: DashboardTimeRange, b: DashboardTimeRange) => (
  a.startDate === b.startDate && a.endDate === b.endDate && a.relativeDate === b.relativeDate
);
