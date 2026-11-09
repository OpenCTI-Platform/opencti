import { FunctionalError } from '../../config/errors';
import { isStrictIsoDate } from './dashboard-variables-resolution';
import type { StoreDashboardTimeRange } from '../workspace/workspace-variables-types';

// A relative date as the front computes it (computeRelativeDate): the select offers a few, an imported dashboard may hold others.
// The count is bounded: beyond, the date computation would make no sense.
const RELATIVE_DATE_REGEXP = /^(days|months|years)-\d{1,4}$/;

export interface DashboardTimeRangeInputLike {
  startDate?: string | null;
  endDate?: string | null;
  relativeDate?: string | null;
}

/**
 * The time range of a dashboard as the front writes it, checked and normalized: a relative date must be one the front
 * can compute, an absolute date a strict ISO-8601 date, and a relative date always comes alone (picking one clears
 * the absolute dates, as the time filters do). Throws a FunctionalError with the given message otherwise.
 */
export const buildDashboardTimeRange = (range: DashboardTimeRangeInputLike | null | undefined, errorMessage: string): StoreDashboardTimeRange => {
  const relativeDate = range?.relativeDate ?? null;
  const startDate = range?.startDate ?? null;
  const endDate = range?.endDate ?? null;
  const isValidDate = (date: string | null) => date === null || isStrictIsoDate(date);
  if ((relativeDate !== null && !RELATIVE_DATE_REGEXP.test(relativeDate)) || !isValidDate(startDate) || !isValidDate(endDate)) {
    throw FunctionalError(errorMessage);
  }
  if (relativeDate !== null) {
    return { relativeDate, startDate: null, endDate: null };
  }
  return { relativeDate: null, startDate, endDate };
};
