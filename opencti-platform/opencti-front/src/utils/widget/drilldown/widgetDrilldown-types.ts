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
   * The range sent as query variables, used to clamp the edge buckets of a time
   * series: the time-series containers ask for `fallbackToDefaultDates`, so an
   * unconfigured dashboard really queries the last 12 months and its first and
   * last buckets are cut at those bounds.
   *
   * It is never the range of a distribution or number bucket -- several
   * containers send no dates at all (`StixRelationshipsDonut`), or send an
   * unrelated one (`StixCoreObjectsNumber` sends `dayAgo()`, which only feeds
   * the 24h variation). For those, `configRange` is the authoritative one.
   */
  range: WidgetDateRange;
  /**
   * The dashboard range that was baked into the widget filters by
   * `computeWidgetFiltersForSelection`, and therefore the one that actually
   * bounded every distribution and number count.
   */
  configRange: WidgetDateRange;
  /** Chart interval, only meaningful for `timeSeries` buckets. */
  interval?: string | null;
  bucket: DrilldownBucket;
  filterKeysSchema: FilterKeysSchema;
  /**
   * The concrete types each abstract type a list page pins actually covers,
   * from `useAuth().schema` (`sdos`, `scrs`).
   *
   * Generic list pages hold less than the widgets count: the relationships list
   * pins `stix-core-relationship` (`Relationships.tsx:281`) while a relationship
   * widget aggregates over `stix-relationship` by default
   * (`stixRelationship.js:36-38`), sightings and refs included; the entities
   * list queries `stixDomainObjects` (`Entities.tsx:45`) while an entity widget
   * counts every `Stix-Core-Object`, observables included. Without knowing which
   * concrete types a destination covers, a widget counting label refs or
   * observables would link to a list that holds none of them.
   */
  subtypesByAbstractType: Record<string, string[]>;
}

export interface ListRouteResolution {
  route: string;
  /**
   * The entity_type value already implied by a dedicated route. The orchestrator
   * removes it from the URL filters because the destination applies it itself.
   */
  consumedEntityType: string | null;
  /**
   * The entity types the destination page pins on its own query. They decide
   * which filter keys survive the URL — the page runs the widget filters through
   * `removeIdAndIncorrectKeysFromFilterGroupObject` against exactly this list.
   */
  scopeTypes: string[];
  /**
   * Whether the destination holds strictly less than the widget counts, so the
   * widget must prove its population is covered before a link can promise the
   * same number. False for dedicated routes, whose type the widget already
   * carried, and for the audit log, which the widget queries directly.
   */
  requiresScopeProof: boolean;
}

export type { FilterGroup };
