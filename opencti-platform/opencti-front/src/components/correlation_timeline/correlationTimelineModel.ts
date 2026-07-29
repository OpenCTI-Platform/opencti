// Shared data model for the correlation timeline view.
// Two entry points feed it: a STIX domain object (objects reached through
// relationships) and a Container (its own objects). Both end up as
// RawCorrelationObject[], so the layout and the filtering logic stay in
// one place.

// Containers holding an object, reached through the `containers` field.
export const CORRELATION_CONTAINER_TYPES = ['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'];

// Entities an object is related to, reached through stix core relationships.
// They are not containers, so they come from a different fan-out, but on the
// timeline they answer the same question: what else does this object show up in.
export const CORRELATION_ENTITY_TYPES = ['Campaign', 'Incident'];

export const CORRELATION_TARGET_TYPES = [
  ...CORRELATION_CONTAINER_TYPES,
  ...CORRELATION_ENTITY_TYPES,
];

export type DateReference = 'functional' | 'technical';

export interface RawCorrelationTarget {
  id: string;
  entityType: string;
  label: string;
  // Functional date: publication for a report, first seen for a campaign or an
  // incident, STIX created date otherwise.
  date: string | null;
  // Technical date: when the object entered the platform.
  technicalDate: string | null;
}

export interface RawCorrelationObject {
  id: string;
  entityType: string;
  parentTypes: readonly string[];
  label: string;
  // Number of containers holding this object in the whole platform: the
  // correlation degree, used to spot over-correlating values.
  containersTotal: number;
  targets: RawCorrelationTarget[];
}

// A "source" is an object of the entity or container being viewed.
export interface CorrelationSource {
  id: string;
  entityType: string;
  label: string;
  containersTotal: number;
  targetIds: string[];
}

// A "target" is a container or an entity sharing at least one source.
export interface CorrelationTarget {
  id: string;
  entityType: string;
  label: string;
  date: Date;
  sourceIds: string[];
}

export interface OverCorrelatedObject {
  id: string;
  entityType: string;
  label: string;
  total: number;
}

export interface SourceTypeCount {
  type: string;
  count: number;
  isObservable: boolean;
}

export interface CorrelationModelOptions {
  // Objects present in more than this many containers are set aside.
  maxContainers: number;
  // Targets sharing fewer than this many objects are dropped.
  minShared: number;
  // Entity types to correlate on. `null` means every type present.
  sourceTypes: string[] | null;
  // Target types to keep, among CORRELATION_TARGET_TYPES.
  targetTypes: string[];
  // Which date positions a target on the axis.
  dateReference: DateReference;
  // The viewed entity itself, which must never appear as a correlated target.
  excludeIds: string[];
}

export interface CorrelationModel {
  sources: CorrelationSource[];
  targets: CorrelationTarget[];
  overCorrelated: OverCorrelatedObject[];
}

// Shape of one side of a core relationship, as selected by both timeline
// queries. Fields are optional because the GraphQL union only exposes them
// through inline fragments.
interface RelationshipSide {
  id?: string;
  entity_type?: string;
  representative?: { readonly main: string } | null;
  created?: string | null;
  created_at?: string | null;
  first_seen?: string | null;
}

// Core relationships are resolved with `fromOrToId`, so they come back in both
// directions: the entity we want is whichever side is not the object itself.
export const pickRelatedTarget = (
  objectId: string,
  from: RelationshipSide | null | undefined,
  to: RelationshipSide | null | undefined,
): RawCorrelationTarget | null => {
  const side = [from, to].find((candidate) => candidate?.id && candidate.id !== objectId);
  if (!side?.id || !side.entity_type || !side.representative) return null;
  return {
    id: side.id,
    entityType: side.entity_type,
    label: side.representative.main,
    // A campaign or an incident is dated by when it started, not by when the
    // analyst typed it in.
    date: side.first_seen ?? side.created ?? side.created_at ?? null,
    technicalDate: side.created_at ?? null,
  };
};

// Entity types actually present among the objects, with how many of each.
// Computed before any filtering so that unchecking a type never makes it
// disappear from the picker.
export const listSourceTypes = (objects: RawCorrelationObject[]): SourceTypeCount[] => {
  const counts = new Map<string, SourceTypeCount>();
  objects.forEach((object) => {
    const existing = counts.get(object.entityType);
    if (existing) {
      existing.count += 1;
    } else {
      counts.set(object.entityType, {
        type: object.entityType,
        count: 1,
        isObservable: object.parentTypes.includes('Stix-Cyber-Observable'),
      });
    }
  });
  return [...counts.values()].sort(
    (a, b) => b.count - a.count || a.type.localeCompare(b.type),
  );
};

export const buildCorrelationModel = (
  objects: RawCorrelationObject[],
  {
    maxContainers,
    minShared,
    sourceTypes,
    targetTypes,
    dateReference,
    excludeIds,
  }: CorrelationModelOptions,
): CorrelationModel => {
  const excluded = new Set(excludeIds);
  const keptSourceTypes = sourceTypes ? new Set(sourceTypes) : null;
  const keptTargetTypes = new Set(targetTypes);
  const overCorrelated: OverCorrelatedObject[] = [];
  const targetMap = new Map<string, CorrelationTarget>();
  const builtSources: CorrelationSource[] = [];

  objects.forEach((object) => {
    // Type filtering comes first: a deselected type should not even show up in
    // the over-correlating list.
    if (keptSourceTypes && !keptSourceTypes.has(object.entityType)) return;
    if (object.containersTotal > maxContainers) {
      overCorrelated.push({
        id: object.id,
        entityType: object.entityType,
        label: object.label,
        total: object.containersTotal,
      });
      return;
    }
    const targetIds: string[] = [];
    object.targets.forEach((target) => {
      if (excluded.has(target.id) || !keptTargetTypes.has(target.entityType)) return;
      const rawDate = dateReference === 'technical'
        ? (target.technicalDate ?? target.date)
        : (target.date ?? target.technicalDate);
      if (!rawDate) return;
      const existing = targetMap.get(target.id);
      if (existing) {
        existing.sourceIds.push(object.id);
      } else {
        targetMap.set(target.id, {
          id: target.id,
          entityType: target.entityType,
          label: target.label,
          date: new Date(rawDate),
          sourceIds: [object.id],
        });
      }
      targetIds.push(target.id);
    });
    if (targetIds.length === 0) return;
    builtSources.push({
      id: object.id,
      entityType: object.entityType,
      label: object.label,
      containersTotal: object.containersTotal,
      targetIds,
    });
  });

  // Keep targets sharing enough objects, then drop the sources left pointing
  // at nothing.
  const targets = [...targetMap.values()]
    .filter((target) => target.sourceIds.length >= minShared)
    .sort((a, b) => a.date.getTime() - b.date.getTime());
  const keptIds = new Set(targets.map((target) => target.id));
  const sources = builtSources
    .map((source) => ({
      ...source,
      targetIds: source.targetIds.filter((id) => keptIds.has(id)),
    }))
    .filter((source) => source.targetIds.length > 0)
    .sort((a, b) => b.targetIds.length - a.targetIds.length);

  return {
    sources,
    targets,
    overCorrelated: overCorrelated.sort((a, b) => b.total - a.total),
  };
};
