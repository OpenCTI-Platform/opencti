import type { IrCriterionDraft, IrDirection } from './irConfigTypes';
import { IR_RELATIONSHIP_TYPES } from './irConstants';

// "Criteria as sentences" view of the scope: a graph criterion is read from the side of the entity that enters.
// outgoing: (starting point) —relationship→ (entity that enters), so the entity is "used by" the starting point.
// incoming: (entity that enters) —relationship→ (starting point), so the entity is one "that uses" the starting point.
// The sentence picks a phrase; the relationship type and the direction of the criterion are derived from it.

export type IrConfigView = 'fields' | 'sentence';

const RELATION_PHRASES: Record<string, { outgoing: string; incoming: string }> = {
  uses: { outgoing: 'used by', incoming: 'that use' },
  targets: { outgoing: 'targeted by', incoming: 'that target' },
  exploits: { outgoing: 'exploited by', incoming: 'that exploit' },
  'attributed-to': { outgoing: 'to which are attributed', incoming: 'attributed to' },
  indicates: { outgoing: 'indicated by', incoming: 'that indicate' },
  object: { outgoing: 'contained in', incoming: 'that contain' },
  'originates-from': { outgoing: 'origin of', incoming: 'originating from' },
  'located-at': { outgoing: 'location of', incoming: 'located at' },
  'variant-of': { outgoing: 'of which are variants', incoming: 'variants of' },
  delivers: { outgoing: 'delivered by', incoming: 'that deliver' },
  drops: { outgoing: 'dropped by', incoming: 'that drop' },
  has: { outgoing: 'present in', incoming: 'that have' },
  'part-of': { outgoing: 'that include', incoming: 'part of' },
  compromises: { outgoing: 'compromised by', incoming: 'that compromise' },
  mitigates: { outgoing: 'mitigated by', incoming: 'that mitigate' },
  'related-to': { outgoing: 'related to (as target)', incoming: 'related to (as source)' },
};

const SEPARATOR = '::';

export interface IrPhraseOption {
  value: string; // <relationship type>::<direction>
  label: string; // English phrase, translated by the screen
}

/**
 * Every phrase the sentence offers: two per relationship type (one per direction).
 * A relationship type without a phrase reads "<type> (from)" / "<type> (to)".
 */
export const relationPhraseOptions = (): IrPhraseOption[] => IR_RELATIONSHIP_TYPES.flatMap((rel) => {
  const phrases = RELATION_PHRASES[rel] ?? { outgoing: `${rel} (from)`, incoming: `${rel} (to)` };
  return [
    { value: `${rel}${SEPARATOR}outgoing`, label: phrases.outgoing },
    { value: `${rel}${SEPARATOR}incoming`, label: phrases.incoming },
  ];
});

/**
 * The phrases a criterion currently reads as. "both" reads as the two phrases of each relationship type.
 */
export const criterionToPhrases = (criterion: Pick<IrCriterionDraft, 'relationship_types' | 'direction'>): string[] => {
  const directions: IrDirection[] = criterion.direction === 'both' ? ['outgoing', 'incoming'] : [criterion.direction];
  return criterion.relationship_types.flatMap((rel) => directions.map((d) => `${rel}${SEPARATOR}${d}`));
};

/**
 * Relationship types and direction from the phrases picked in the sentence.
 * The criterion has one direction for all its types: phrases of both directions make it "both".
 */
export const phrasesToCriterion = (phrases: string[]): Pick<IrCriterionDraft, 'relationship_types' | 'direction'> => {
  const parsed = phrases.map((p) => {
    const [rel, direction] = p.split(SEPARATOR);
    return { rel, direction: direction as IrDirection };
  });
  const relationship_types = Array.from(new Set(parsed.map((p) => p.rel)));
  const directions = new Set(parsed.map((p) => p.direction));
  let direction: IrDirection = 'outgoing';
  if (directions.size > 1) direction = 'both';
  else if (directions.has('incoming')) direction = 'incoming';
  return { relationship_types, direction };
};

/**
 * Phrases that the derived criterion brings in addition to what was picked (a "both" direction applies to every type).
 * Shown under the sentence, so that the user sees what the engine will really evaluate.
 */
export const impliedPhrases = (picked: string[]) => {
  const implied = criterionToPhrases(phrasesToCriterion(picked));
  return implied.filter((p) => !picked.includes(p));
};

// Number of filters of a serialized filter group (nested groups included), for the sentence
export const countFilters = (filters: string | null): number => {
  if (!filters) return 0;
  try {
    const count = (group: { filters?: unknown[]; filterGroups?: unknown[] }): number => (group.filters?.length ?? 0)
      + (group.filterGroups ?? []).reduce<number>((n, g) => n + count(g as { filters?: unknown[]; filterGroups?: unknown[] }), 0);
    return count(JSON.parse(filters));
  } catch {
    return 0;
  }
};

export const IN_REQUIREMENT_START = '__in_requirement__';

// The starting points of a criterion: its subject groups, and the entities already in the requirement (second hop)
export const criterionToStarts = (criterion: Pick<IrCriterionDraft, 'from_group_ids' | 'from_in_requirement'>) => [
  ...criterion.from_group_ids,
  ...(criterion.from_in_requirement ? [IN_REQUIREMENT_START] : []),
];

export const startsToCriterion = (starts: string[]): Pick<IrCriterionDraft, 'from_group_ids' | 'from_in_requirement'> => ({
  from_group_ids: starts.filter((s) => s !== IN_REQUIREMENT_START),
  from_in_requirement: starts.includes(IN_REQUIREMENT_START),
});

// Where the configuration view is remembered: per requirement once it exists
const viewKey = (irId: string) => `opencti-ir-config-view-${irId}`;

export const readConfigView = (irId: string): IrConfigView => {
  try {
    return localStorage.getItem(viewKey(irId)) === 'sentence' ? 'sentence' : 'fields';
  } catch {
    return 'fields';
  }
};

export const writeConfigView = (irId: string, view: IrConfigView) => {
  try {
    localStorage.setItem(viewKey(irId), view);
  } catch {
    // storage unavailable: the view falls back to the fields
  }
};
