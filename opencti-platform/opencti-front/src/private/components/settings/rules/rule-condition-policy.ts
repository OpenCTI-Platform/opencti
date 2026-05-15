import type { RuleCapability, RuleSlotCapability } from './rule-capabilities.generated';

export type ConditionFamilyPriority = 'HIGH' | 'MEDIUM';

export type ConditionFamilyId =
  | 'confidence-threshold'
  | 'creator-author-restriction'
  | 'source-restriction'
  | 'marking-tlp'
  | 'entity-type-restriction'
  | 'sighting-specific';

export interface ConditionFamilyDefinition {
  id: ConditionFamilyId;
  label: string;
  priority: ConditionFamilyPriority;
  allowedSlotKinds: Array<'entity' | 'relationship'>;
  requiresSightingRule?: boolean;
  requiresMultiTypeEntitySlot?: boolean;
  preferredFilterKeys: string[];
}

export interface EligibleConditionFamily extends ConditionFamilyDefinition {
  availableFilterKeys: string[];
}

export const CONDITION_FAMILY_DEFINITIONS: ConditionFamilyDefinition[] = [
  {
    id: 'confidence-threshold',
    label: 'Confidence threshold filtering',
    priority: 'HIGH',
    allowedSlotKinds: ['entity', 'relationship'],
    preferredFilterKeys: ['confidence'],
  },
  {
    id: 'creator-author-restriction',
    label: 'Creator/author restrictions',
    priority: 'HIGH',
    allowedSlotKinds: ['entity', 'relationship'],
    preferredFilterKeys: ['createdBy', 'creator_id', 'created_at'],
  },
  {
    id: 'source-restriction',
    label: 'Source-based restrictions',
    priority: 'MEDIUM',
    allowedSlotKinds: ['entity', 'relationship'],
    preferredFilterKeys: [
      'x_opencti_source',
      'x_opencti_source_name',
      'source',
      'source_name',
    ],
  },
  {
    id: 'marking-tlp',
    label: 'Marking/TLP-based conditions',
    priority: 'MEDIUM',
    allowedSlotKinds: ['entity', 'relationship'],
    preferredFilterKeys: ['objectMarking', 'x_opencti_marking', 'tlp'],
  },
  {
    id: 'entity-type-restriction',
    label: 'Entity type restrictions',
    priority: 'HIGH',
    allowedSlotKinds: ['entity'],
    requiresMultiTypeEntitySlot: true,
    preferredFilterKeys: ['entity_type'],
  },
  {
    id: 'sighting-specific',
    label: 'Sighting-specific conditions',
    priority: 'MEDIUM',
    allowedSlotKinds: ['relationship'],
    requiresSightingRule: true,
    preferredFilterKeys: [
      'first_seen',
      'last_seen',
      'confidence',
      'status',
      'x_opencti_status',
      'qualification',
      'x_opencti_qualification',
      'x_opencti_detection',
    ],
  },
];

const intersectKeys = (preferred: string[], available: string[]): string[] => {
  const availableSet = new Set(available);
  return preferred.filter((k) => availableSet.has(k));
};

export const isConditionFamilyAllowed = (
  family: ConditionFamilyDefinition,
  ruleCapability: RuleCapability,
  slot: RuleSlotCapability,
): boolean => {
  if (!family.allowedSlotKinds.includes(slot.kind)) return false;
  if (family.requiresSightingRule && !ruleCapability.hasSightingEdge) return false;
  if (family.requiresMultiTypeEntitySlot && !slot.multiType) return false;
  return true;
};

export const getEligibleConditionFamilies = (
  ruleCapability: RuleCapability,
  slot: RuleSlotCapability,
  availableFilterKeys: string[],
): EligibleConditionFamily[] => {
  return CONDITION_FAMILY_DEFINITIONS
    .filter((family) => isConditionFamilyAllowed(family, ruleCapability, slot))
    .map((family) => ({
      ...family,
      availableFilterKeys: intersectKeys(family.preferredFilterKeys, availableFilterKeys),
    }))
    .filter((family) => family.availableFilterKeys.length > 0);
};

export const getLockedEntityTypeFilterValues = (slot: RuleSlotCapability): string[] => {
  if (slot.kind !== 'entity') return [];
  return slot.allowedEntityTypes;
};

export const getConditionFamilyById = (
  id: ConditionFamilyId,
): ConditionFamilyDefinition | undefined => {
  return CONDITION_FAMILY_DEFINITIONS.find((family) => family.id === id);
};
