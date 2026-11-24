// A weighting adjustment of the preset scoring: the weighting of the entities a rule brings in changes by some value
// when they also have a property (filters) or are linked to chosen entities, directly or through one entity in between.
// Pure data and conversions: labels are English strings, translated at render time.
import { emptyGroup, emptyRule, newId, type IrDirection, type IrEntityOption, type IrGroupDraft, type IrRuleDraft } from './irConfigTypes';
import { IR_RELATIONSHIP_TYPES } from './irConstants';

export type IrHops = 'direct' | 'two';
export type IrHopDirection = 'outgoing' | 'incoming'; // outgoing: the flagged entity is the source of the relationship

export interface IrAdjustment {
  id: string; // the id of the rule it is saved as
  criterionId: string;
  points: number;
  appliesTo: string | null; // one of the flagged types; null: any of them
  kind: 'property' | 'linked' | null;
  filters: string | null;
  hops: IrHops | null;
  rel1: string | null;
  dir1: IrHopDirection | null;
  bi1: boolean; // the first relationship counts in either direction
  inter: string | null; // the type of the entity in between
  rel2: string | null; // from the entity in between to the end
  ends: IrEntityOption[];
}

// Who reads what: "the malware uses …" (outgoing) and "the malware is used by …" (incoming)
export const IR_VERB_PHRASES: Record<string, { outgoing: string; incoming: string }> = {
  uses: { outgoing: 'uses', incoming: 'is used by' },
  targets: { outgoing: 'targets', incoming: 'is targeted by' },
  'originates-from': { outgoing: 'originates from', incoming: 'is the origin of' },
  exploits: { outgoing: 'exploits', incoming: 'is exploited by' },
  indicates: { outgoing: 'indicates', incoming: 'is indicated by' },
  'variant-of': { outgoing: 'is a variant of', incoming: 'has as a variant' },
  'related-to': { outgoing: 'is related to', incoming: 'is related to' },
  'attributed-to': { outgoing: 'is attributed to', incoming: 'has attributed to it' },
  has: { outgoing: 'has', incoming: 'is present in' },
  delivers: { outgoing: 'delivers', incoming: 'is delivered by' },
  drops: { outgoing: 'drops', incoming: 'is dropped by' },
  'located-at': { outgoing: 'is located in', incoming: 'is the location of' },
  'part-of': { outgoing: 'is part of', incoming: 'includes' },
  'communicates-with': { outgoing: 'communicates with', incoming: 'is contacted by' },
  compromises: { outgoing: 'compromises', incoming: 'is compromised by' },
  impersonates: { outgoing: 'impersonates', incoming: 'is impersonated by' },
  mitigates: { outgoing: 'mitigates', incoming: 'is mitigated by' },
  remediates: { outgoing: 'remediates', incoming: 'is remediated by' },
  'belongs-to': { outgoing: 'belongs to', incoming: 'has as a member' },
  'derived-from': { outgoing: 'is derived from', incoming: 'is the source of' },
  'authored-by': { outgoing: 'is authored by', incoming: 'is the author of' },
  hosts: { outgoing: 'hosts', incoming: 'is hosted by' },
  owns: { outgoing: 'owns', incoming: 'is owned by' },
  'beacons-to': { outgoing: 'beacons to', incoming: 'receives beacons from' },
  downloads: { outgoing: 'downloads', incoming: 'is downloaded by' },
};
// Read the same both ways: always matched in either direction, no toggle
export const IR_SYMMETRIC_RELATIONSHIPS = ['related-to'];
// Containment is not a relationship the path search follows
const HOP_RELATIONSHIPS = IR_RELATIONSHIP_TYPES.filter((r) => r !== 'object' && IR_VERB_PHRASES[r]);

export const verbPhrase = (rel: string, dir: IrHopDirection) => IR_VERB_PHRASES[rel]?.[dir] ?? rel;
export const inversePhrase = (rel: string, dir: IrHopDirection) => verbPhrase(rel, dir === 'outgoing' ? 'incoming' : 'outgoing');
// The catalog keys of the phrases: their own keys, as some phrases ("targets") already name other things
export const verbKey = (rel: string, dir: IrHopDirection) => `ir_verb_${verbPhrase(rel, dir)}`;
export const inverseKey = (rel: string, dir: IrHopDirection) => `ir_verb_${inversePhrase(rel, dir)}`;
export const isSymmetric = (rel: string | null) => !!rel && IR_SYMMETRIC_RELATIONSHIPS.includes(rel);

// The relationship types the platform allows from one entity type to another
export type IrRelationMapping = (from: string, to: string) => readonly string[];

export interface IrHopOption {
  value: string; // `${rel}|${dir}`
  rel: string;
  dir: IrHopDirection;
  endTypes: string[];
}
export const hopValue = (rel: string, dir: IrHopDirection) => `${rel}|${dir}`;

/**
 * The relationships every one of the source types has, read from their side, with the types they lead to.
 * With several source types (any flagged type), only what all of them have: an adjustment never silently misses a type.
 */
export const hopOptions = (sources: string[], allTypes: string[], mapping: IrRelationMapping, directions: IrHopDirection[] = ['outgoing', 'incoming']): IrHopOption[] => {
  if (sources.length === 0) return [];
  return HOP_RELATIONSHIPS.flatMap((rel) => directions
    .filter((dir) => !(isSymmetric(rel) && dir === 'incoming'))
    .map((dir) => ({
      value: hopValue(rel, dir),
      rel,
      dir,
      endTypes: allTypes.filter((type) => sources.every((source) => (dir === 'outgoing' ? mapping(source, type) : mapping(type, source)).includes(rel))),
    })))
    .filter((option) => option.endTypes.length > 0);
};

// The engine follows the second relationship from the entity in between outward only
export const secondHopOptions = (inter: string, allTypes: string[], mapping: IrRelationMapping) => hopOptions([inter], allTypes, mapping, ['outgoing']);

// The types the first relationship leads to that have a second relationship of their own
export const intermediateTypes = (first: IrHopOption | undefined, allTypes: string[], mapping: IrRelationMapping) => (first
  ? first.endTypes.filter((type) => secondHopOptions(type, allTypes, mapping).length > 0)
  : []);

export const emptyAdjustment = (criterionId: string): IrAdjustment => ({
  id: newId('b'),
  criterionId,
  points: 10,
  appliesTo: null,
  kind: null,
  filters: null,
  hops: null,
  rel1: null,
  dir1: null,
  bi1: false,
  inter: null,
  rel2: null,
  ends: [],
});

// A choice clears the ones after it
const ORDER = ['appliesTo', 'kind', 'hops', 'first', 'inter', 'rel2'] as const;
export type IrAdjustmentStep = typeof ORDER[number];
export const choose = (adjustment: IrAdjustment, step: IrAdjustmentStep, patch: Partial<IrAdjustment>): IrAdjustment => {
  const later = ORDER.slice(ORDER.indexOf(step) + 1);
  const cleared: Partial<IrAdjustment> = { ends: [] };
  if (later.includes('kind')) cleared.kind = null;
  if (later.includes('kind') || step === 'kind') cleared.filters = null;
  if (later.includes('hops')) cleared.hops = null;
  if (later.includes('first')) Object.assign(cleared, { rel1: null, dir1: null });
  if (later.includes('first') || step === 'first') cleared.bi1 = false;
  if (later.includes('inter')) cleared.inter = null;
  if (later.includes('rel2')) cleared.rel2 = null;
  return { ...adjustment, ...cleared, ...patch };
};

// A direct link is always matched in either direction by the engine
export const firstHopBothWays = (adjustment: IrAdjustment) => adjustment.hops === 'direct' || adjustment.bi1 || isSymmetric(adjustment.rel1);

export const isAdjustmentComplete = (a: IrAdjustment): boolean => {
  if (a.kind === 'property') return !!a.filters;
  if (a.kind !== 'linked' || !a.rel1 || !a.dir1 || a.ends.length === 0) return false;
  return a.hops === 'direct' || (a.hops === 'two' && !!a.inter && !!a.rel2);
};

// The subject group a direct link points to: it holds the chosen entities, the user never sees it
const ADJUSTMENT_GROUP_PREFIX = 'ga-';
export const isAdjustmentGroup = (group: IrGroupDraft) => group.id.startsWith(ADJUSTMENT_GROUP_PREFIX);

/**
 * The rule an adjustment is saved as, and the subject group of a direct link.
 * Property: filters. Direct link: a link to a context group of the chosen entities (either direction).
 * Through an entity: a path condition, the type in between included.
 */
export const adjustmentToRule = (a: IrAdjustment, name: string): { rule: IrRuleDraft; group: IrGroupDraft | null } => {
  const rule: IrRuleDraft = {
    ...emptyRule(),
    id: a.id,
    name,
    applies_to_types: a.appliesTo ? [a.appliesTo] : [],
    applies_to_criterion_id: a.criterionId,
    points: a.points,
    enabled: true,
  };
  if (a.kind === 'property') return { rule: { ...rule, filters: a.filters }, group: null };
  if (a.kind !== 'linked' || !a.rel1 || !a.dir1) return { rule, group: null };
  if (a.hops === 'direct') {
    const group: IrGroupDraft = { ...emptyGroup(), id: `${ADJUSTMENT_GROUP_PREFIX}${a.id}`, name, kind: 'list', role: 'context', entities: a.ends };
    return { rule: { ...rule, link: { relationship_types: [a.rel1], group_ids: [group.id] } }, group };
  }
  const direction: IrDirection = firstHopBothWays(a) ? 'both' : a.dir1;
  return {
    rule: {
      ...rule,
      path_condition: {
        relationship_types: [a.rel1],
        direction,
        intermediate_types: a.inter ? [a.inter] : [],
        target_relationship_type: a.rel2 ?? '',
        targets: a.ends,
        target_group_ids: [],
      },
    },
    group: null,
  };
};

// The engine does not keep which way a direct link was read ("is present in" or "has"): the platform's relationship
// schema says which reading leads to the chosen entities
export type IrDirectionResolver = (rel: string, endTypes: string[]) => IrHopDirection;
export const directionResolver = (sources: string[], allTypes: string[], mapping: IrRelationMapping): IrDirectionResolver => (rel, endTypes) => {
  const options = hopOptions(sources, allTypes, mapping).filter((o) => o.rel === rel);
  return (options.find((o) => endTypes.some((type) => o.endTypes.includes(type))) ?? options[0])?.dir ?? 'outgoing';
};

// Back from a saved rule, to edit it
export const ruleToAdjustment = (rule: IrRuleDraft, groups: IrGroupDraft[], resolveDirection?: IrDirectionResolver): IrAdjustment => {
  const base: IrAdjustment = { ...emptyAdjustment(rule.applies_to_criterion_id ?? ''), id: rule.id, points: rule.points, appliesTo: rule.applies_to_types[0] ?? null };
  if (rule.path_condition) {
    const path = rule.path_condition;
    const both = path.direction === 'both';
    return {
      ...base,
      kind: 'linked',
      hops: 'two',
      rel1: path.relationship_types[0] ?? null,
      dir1: both ? 'outgoing' : path.direction as IrHopDirection,
      bi1: both && !isSymmetric(path.relationship_types[0] ?? null),
      inter: path.intermediate_types[0] ?? null,
      rel2: path.target_relationship_type || null,
      ends: path.targets,
    };
  }
  if (rule.link) {
    const group = groups.find((g) => g.id === rule.link?.group_ids[0]);
    const rel1 = rule.link.relationship_types[0] ?? null;
    const ends = group?.entities ?? [];
    const dir1 = rel1 && resolveDirection ? resolveDirection(rel1, ends.map((e) => e.type)) : 'outgoing';
    return { ...base, kind: 'linked', hops: 'direct', rel1, dir1, bi1: true, ends };
  }
  return { ...base, kind: 'property', filters: rule.filters };
};

// Saving or removing adjustments: their groups follow them
export const withAdjustmentGroups = (groups: IrGroupDraft[], rules: IrRuleDraft[], saved: IrGroupDraft | null): IrGroupDraft[] => {
  const kept = groups.filter((g) => g.id !== saved?.id);
  const all = saved ? [...kept, saved] : kept;
  const used = new Set(rules.flatMap((r) => r.link?.group_ids ?? []));
  return all.filter((g) => !isAdjustmentGroup(g) || used.has(g.id));
};
