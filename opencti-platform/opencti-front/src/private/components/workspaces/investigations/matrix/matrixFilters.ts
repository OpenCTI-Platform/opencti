import { NO_AUTHOR_ID, NO_MARKING_ID, type ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { isOutsideTimeRange } from '../../../../../components/graph/utils/graphTimeRange';
import type { GraphLink } from '../../../../../components/graph/graph.types';
import { defaultDate } from '../../../../../utils/defaultRepresentatives';
import { jsDate } from '../../../../../utils/Time';
import type { ScoringLink } from './ttpAnalyser';

export type MatrixRelationshipType = 'uses' | 'indicates' | 'object';

export const MATRIX_RELATIONSHIP_TYPES: MatrixRelationshipType[] = ['uses', 'indicates', 'object'];

export interface InvestigationMatrixFilters {
  disabledEntityTypes: string[];
  disabledRelationshipTypes: MatrixRelationshipType[];
  disabledMarkings: string[];
  disabledCreators: string[];
  /** ISO dates; undefined = the whole range. */
  timeRange?: [string, string];
}

export const DEFAULT_MATRIX_FILTERS: InvestigationMatrixFilters = {
  disabledEntityTypes: [],
  disabledRelationshipTypes: [],
  disabledMarkings: [],
  disabledCreators: [],
};

export const hasActiveMatrixFilters = (filters: InvestigationMatrixFilters): boolean => {
  return filters.disabledEntityTypes.length > 0
    || filters.disabledRelationshipTypes.length > 0
    || filters.disabledMarkings.length > 0
    || filters.disabledCreators.length > 0
    || !!filters.timeRange;
};

export interface MatrixFilterOptions {
  entityTypes: string[];
  relationshipTypes: MatrixRelationshipType[];
  markings: { id: string; definition: string }[];
  authors: { id: string; name: string }[];
  /** Scoring links as the time range scale reads them. */
  datedLinks: Pick<GraphLink, 'parent_types' | 'defaultDate'>[];
}

// What the marking and author filters read: the link and its linked entity, never the attack pattern.
// A contains link carries no marking and no author of its own: it holds those of its container,
// which is its linked entity.
const linkElements = ({ relationship, entity }: ScoringLink) => {
  return relationship.relationship_type === 'object' ? [entity] : [relationship, entity];
};

// As in the graph, an element without marking or author stands under "None".
const markingsOf = (object: ObjectToParse, noneLabel: string) => {
  const markings = object.objectMarking ?? [];
  if (markings.length === 0) return [{ id: NO_MARKING_ID, definition: noneLabel }];
  return markings.map(({ id, definition }) => ({ id, definition }));
};

const authorOf = (object: ObjectToParse, noneLabel: string) => {
  return object.createdBy?.id ? { id: object.createdBy.id, name: object.createdBy.name } : { id: NO_AUTHOR_ID, name: noneLabel };
};

const linkMarkings = (link: ScoringLink, noneLabel = '') => linkElements(link).flatMap((object) => markingsOf(object, noneLabel));

const linkAuthors = (link: ScoringLink, noneLabel = '') => linkElements(link).map((object) => authorOf(object, noneLabel));

const relationshipDate = (relationship: ObjectToParse) => jsDate(defaultDate(relationship));

// One pass, first occurrence kept: an investigation can hold thousands of scoring links.
const uniqueById = <T extends { id: string }>(items: T[]) => {
  const seen = new Set<string>();
  return items.filter(({ id }) => {
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
};

/** What the filter lists offer: only what the scoring links of the investigation hold. */
export const getMatrixFilterOptions = (links: ScoringLink[], noneLabel: string): MatrixFilterOptions => {
  const relationshipTypes = new Set(links.map(({ relationship }) => relationship.relationship_type));
  return {
    entityTypes: [...new Set(links.map(({ entity }) => entity.entity_type))].sort(),
    relationshipTypes: MATRIX_RELATIONSHIP_TYPES.filter((type) => relationshipTypes.has(type)),
    markings: uniqueById(links.flatMap((link) => linkMarkings(link, noneLabel)))
      .sort((a, b) => a.definition.localeCompare(b.definition)),
    authors: uniqueById(links.flatMap((link) => linkAuthors(link, noneLabel)))
      .sort((a, b) => a.name.localeCompare(b.name)),
    // One entry per relationship, even when it scores both of its ends.
    datedLinks: uniqueById(links.map(({ relationship }) => relationship))
      .map((relationship) => ({ parent_types: relationship.parent_types, defaultDate: relationshipDate(relationship) })),
  };
};

const isLinkKept = (link: ScoringLink, filters: InvestigationMatrixFilters, interval?: [Date, Date]) => {
  return !filters.disabledRelationshipTypes.includes(link.relationship.relationship_type as MatrixRelationshipType)
    && !filters.disabledEntityTypes.includes(link.entity.entity_type)
    && !linkMarkings(link).some(({ id }) => filters.disabledMarkings.includes(id))
    && !linkAuthors(link).some(({ id }) => filters.disabledCreators.includes(id))
    && !(interval && isOutsideTimeRange(relationshipDate(link.relationship), interval));
};

/** The stored time range as dates; undefined for the whole range. */
export const matrixFiltersInterval = (filters: InvestigationMatrixFilters): [Date, Date] | undefined => {
  return filters.timeRange ? [jsDate(filters.timeRange[0]), jsDate(filters.timeRange[1])] : undefined;
};

/** The scoring links the filters keep. */
export const filterScoringLinks = (links: ScoringLink[], filters: InvestigationMatrixFilters): ScoringLink[] => {
  if (!hasActiveMatrixFilters(filters)) return links;
  const interval = matrixFiltersInterval(filters);
  // A "uses" between two attack patterns scores both ends: the relationship goes as soon as one of
  // its links is dropped, so a filtered-out entity never shows in a hover list.
  const dropped = new Set(
    links
      .filter((link) => !isLinkKept(link, filters, interval))
      .map(({ relationship }) => relationship.id),
  );
  if (dropped.size === 0) return links;
  return links.filter(({ relationship }) => !dropped.has(relationship.id));
};
