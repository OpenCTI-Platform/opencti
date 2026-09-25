import type { FilterGroup } from '../../filters/filtersHelpers-types';
import type { WidgetDataSelection, WidgetPerspective } from '../widget';
import type { FilterDefinition } from '../../hooks/useAuth';

/** Filter keys schema as exposed by `useAuth().schema.filterKeysSchema`. */
export type FilterKeysSchema = Map<string, Map<string, FilterDefinition>>;

/** The widget's own global date range, used to clamp edge buckets. */
export interface WidgetDateRange {
  startDate?: string | null;
  endDate?: string | null;
}

/**
 * The clicked surface.
 * - `timeSeries`: a point/bar of a time-series chart. `date` is the value returned
 *   by the API for that point (local period start expressed in UTC — see spec §5).
 * - `distribution`: a slice/bar/row of a distribution widget. `rawValue` is the
 *   untransformed `label` from the query, never the displayed label.
 * - `total`: the single number of a `number` widget.
 */
export type DrilldownBucket
  = | { kind: 'timeSeries'; date: string }
    | { kind: 'distribution'; rawValue: string | null; entityId?: string | null }
    | { kind: 'total' };

export interface DrilldownInput {
  perspective: WidgetPerspective;
  /** The resolved data selection this bucket belongs to. */
  dataSelection: WidgetDataSelection;
  /**
   * The date range the widget query actually used — not the dashboard config.
   *
   * Recomputing it from the config would break the invariant twice over: the
   * time-series containers request their range with `fallbackToDefaultDates`
   * (so an unconfigured dashboard really queries the last 12 months, and edge
   * buckets must be clamped to that), and `monthsAgo(12)` / `now()` re-evaluated
   * at click time would no longer be the instants the count was computed from.
   */
  range: WidgetDateRange;
  /** Chart interval, only meaningful for `timeSeries` buckets. */
  interval?: string | null;
  bucket: DrilldownBucket;
  filterKeysSchema: FilterKeysSchema;
}

export interface ListRouteResolution {
  route: string;
  /**
   * The entity_type value already implied by a dedicated route. The orchestrator
   * removes it from the URL filters because the destination applies it itself.
   */
  consumedEntityType: string | null;
}

export type { FilterGroup };
