// Preset rule catalogue for the "pick a PIR type, then pick preset rules" creation flow.
// Pure data plus lookups: labels are English strings, translated at render time.
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

export type IrPirType = 'threat_landscape' | 'adversary' | 'malware' | 'vulnerability' | 'credential' | 'fraud' | 'threat_custom';

export interface IrPirTypeDefinition {
  key: IrPirType;
  label: string;
  description: string;
  subject: string;
  flags: string[]; // entity types the requirement flags; empty for threat_custom (chosen on step 1)
  enabled: boolean;
}

export type IrValueKind = 'none' | 'entities' | 'entitiesOrType' | 'vocabulary' | 'labels' | 'keywords' | 'text' | 'number' | 'containerTypes' | 'filters';

// direction follows the graph-criterion meaning:
// incoming: the flagged entity is the source (malware -targets-> sector)
// outgoing: the flagged entity is the target (software -has-> vulnerability)
export type IrRuleBuild =
  | { kind: 'oneOf' }
  | { kind: 'entityFilter'; key: string; operator: 'eq' | 'gte' }
  | { kind: 'motivation' } // OR of primary_motivation and secondary_motivations
  | { kind: 'fixedFilter'; filters: FilterGroup }
  | { kind: 'keywords' }
  | { kind: 'linked'; relationships: string[]; direction: 'incoming' | 'outgoing' }
  | { kind: 'linkedViaFilter'; relationships: string[]; direction: 'incoming' | 'outgoing'; anchorType: string; anchorKey: string }
  | { kind: 'container' }
  | { kind: 'containerFixed'; filters: FilterGroup }
  | { kind: 'indicated' }
  | { kind: 'domains' }
  | { kind: 'filters' }; // advanced search criteria: the standard OpenCTI filters

export interface IrPresetRule {
  key: string;
  sentence: string; // "When it targets"
  verb: string; // used when naming: "targeting"; "{v}" places the values, otherwise they follow the verb
  value: IrValueKind;
  valueTypes?: string[]; // for 'one-of' the flagged types are used instead
  vocabularyField?: string;
  build: IrRuleBuild;
  appliesTo: string[] | 'any'; // 'any': whatever type the requirement flags
  pirTypes: IrPirType[] | 'all';
}

const THREAT_TYPES = ['Campaign', 'Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual'];
const T = THREAT_TYPES;
const ACTORS = ['Threat-Actor-Group', 'Threat-Actor-Individual'];
const ATTRIBUTION_TYPES = ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual'];
const CREDENTIAL_FLAGS = ['User-Account', 'Email-Addr', 'Credential'];

export const IR_PIR_TYPES: IrPirTypeDefinition[] = [
  {
    key: 'threat_landscape',
    label: 'Threat landscape',
    description: 'Malware, attack patterns, vulnerabilities and containers targeting the locations and sectors you monitor.',
    subject: 'Threats',
    flags: ['Campaign', 'Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Malware'],
    enabled: true,
  },
  {
    key: 'adversary',
    label: 'Adversary intelligence',
    description: 'Threat actor methodologies, groups, and motivations.',
    subject: 'Adversaries',
    flags: ['Threat-Actor-Group', 'Threat-Actor-Individual', 'Intrusion-Set', 'Campaign'],
    enabled: true,
  },
  {
    key: 'malware',
    label: 'Malware intelligence',
    description: 'Malware families, technical indicators, and infrastructure updates.',
    subject: 'Malware',
    flags: ['Malware'],
    enabled: true,
  },
  {
    key: 'vulnerability',
    label: 'Vulnerability intelligence',
    description: 'Pre-exploit vulnerabilities and patch prioritization.',
    subject: 'Vulnerabilities',
    flags: ['Vulnerability'],
    enabled: true,
  },
  {
    key: 'credential',
    label: 'Credential intelligence',
    description: 'Compromised identity exposures and leak monitoring.',
    subject: 'Credentials',
    flags: CREDENTIAL_FLAGS,
    enabled: true,
  },
  {
    key: 'fraud',
    label: 'Fraud intelligence',
    description: 'Underground marketplace activity and asset illicit sales.',
    subject: 'Fraud assets',
    flags: [],
    enabled: false,
  },
  {
    key: 'threat_custom',
    label: 'Threat custom',
    description: 'Choose what to flag, then use any rule.',
    subject: 'Entities',
    flags: [], // chosen on step 1 among every entity type of the platform
    enabled: true,
  },
];

// Every flag a "Threat custom" requirement can choose from (the union of the typed flags).

const entityFilter = (key: string, operator: 'eq' | 'gte' = 'eq'): IrRuleBuild => ({ kind: 'entityFilter', key, operator });

// Advanced search criteria inside a group. Outside a group, they are an item of their own (not a rule of the catalogue).
export const ADVANCED_RULE_KEY = 'advanced';

export const IR_PRESET_RULES: IrPresetRule[] = [
  { key: ADVANCED_RULE_KEY, sentence: 'Advanced search criteria', verb: 'matching custom filters', value: 'filters', build: { kind: 'filters' }, appliesTo: 'any', pirTypes: 'all' },
  // shared rules
  { key: 'one-of', sentence: 'Is one of', verb: ':', value: 'entities', build: { kind: 'oneOf' }, appliesTo: 'any', pirTypes: 'all' },
  { key: 'has-label', sentence: 'Has the label', verb: 'labelled', value: 'labels', build: entityFilter('objectLabel'), appliesTo: 'any', pirTypes: 'all' },
  { key: 'mentions', sentence: 'Its description mentions', verb: 'mentioning', value: 'keywords', build: { kind: 'keywords' }, appliesTo: 'any', pirTypes: 'all' },
  {
    key: 'in-container',
    sentence: 'Is mentioned in',
    verb: 'in',
    value: 'containerTypes',
    valueTypes: ['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'],
    build: { kind: 'container' },
    appliesTo: 'any',
    pirTypes: 'all',
  },
  // threat landscape and adversary
  {
    key: 'targets',
    sentence: 'When it targets',
    verb: 'targeting',
    value: 'entitiesOrType',
    valueTypes: ['Sector', 'Country', 'Region', 'City', 'Organization'],
    build: { kind: 'linked', relationships: ['targets'], direction: 'incoming' },
    appliesTo: [...T, 'Malware'],
    pirTypes: ['threat_landscape', 'adversary', 'malware'],
  },
  {
    key: 'motivation',
    sentence: 'When its motivation is',
    verb: 'motivated by',
    value: 'vocabulary',
    vocabularyField: 'primary_motivation',
    build: { kind: 'motivation' },
    appliesTo: [...ACTORS, 'Intrusion-Set'],
    pirTypes: ['threat_landscape', 'adversary'],
  },
  {
    key: 'attributed-motivation',
    sentence: 'When it is attributed to an actor motivated by',
    verb: 'attributed to actors motivated by',
    value: 'vocabulary',
    vocabularyField: 'primary_motivation',
    build: { kind: 'linkedViaFilter', relationships: ['attributed-to'], direction: 'incoming', anchorType: 'Threat-Actor-Group', anchorKey: 'primary_motivation' },
    appliesTo: ['Campaign'],
    pirTypes: ['threat_landscape'],
  },
  {
    key: 'originates',
    sentence: 'When it originates from',
    verb: 'originating from',
    value: 'entitiesOrType',
    valueTypes: ['Country', 'Region'],
    build: { kind: 'linked', relationships: ['originates-from'], direction: 'incoming' },
    appliesTo: ['Campaign', 'Intrusion-Set', 'Malware'],
    pirTypes: ['threat_landscape'],
  },
  // adversary and malware
  {
    key: 'uses',
    sentence: 'When it uses',
    verb: 'using',
    value: 'entitiesOrType',
    valueTypes: ['Malware', 'Tool', 'Attack-Pattern'],
    build: { kind: 'linked', relationships: ['uses'], direction: 'incoming' },
    appliesTo: [...T, 'Malware'],
    pirTypes: ['adversary', 'malware'],
  },
  {
    key: 'indicated',
    sentence: 'When an indicator indicates it',
    verb: 'with new indicators',
    value: 'none',
    build: { kind: 'indicated' },
    appliesTo: [...T, 'Malware'],
    pirTypes: ['adversary', 'malware'],
  },
  // adversary
  {
    key: 'targets-vulnerability',
    sentence: 'When it targets the vulnerability',
    verb: 'targeting',
    value: 'entities',
    valueTypes: ['Vulnerability'],
    build: { kind: 'linked', relationships: ['targets'], direction: 'incoming' },
    appliesTo: T,
    pirTypes: ['adversary'],
  },
  {
    key: 'attributed-to',
    sentence: 'When it is attributed to',
    verb: 'attributed to',
    value: 'entities',
    valueTypes: ATTRIBUTION_TYPES,
    build: { kind: 'linked', relationships: ['attributed-to'], direction: 'incoming' },
    appliesTo: ['Campaign', 'Intrusion-Set'],
    pirTypes: ['adversary'],
  },
  {
    key: 'sophistication',
    sentence: 'When its sophistication is',
    verb: 'of sophistication',
    value: 'vocabulary',
    vocabularyField: 'sophistication',
    build: entityFilter('sophistication'),
    appliesTo: ACTORS,
    pirTypes: ['adversary'],
  },
  {
    key: 'resource-level',
    sentence: 'When its resource level is',
    verb: 'with resources',
    value: 'vocabulary',
    vocabularyField: 'resource_level',
    build: entityFilter('resource_level'),
    appliesTo: [...ACTORS, 'Intrusion-Set'],
    pirTypes: ['adversary'],
  },
  {
    key: 'impersonates',
    sentence: 'When it impersonates',
    verb: 'impersonating',
    value: 'entities',
    valueTypes: ['Organization'],
    build: { kind: 'linked', relationships: ['impersonates'], direction: 'incoming' },
    appliesTo: ['Threat-Actor-Group'],
    pirTypes: ['adversary'],
  },
  // malware
  {
    key: 'malware-type',
    sentence: 'When its malware type is',
    verb: 'of type',
    value: 'vocabulary',
    vocabularyField: 'malware_types',
    build: entityFilter('malware_types'),
    appliesTo: ['Malware'],
    pirTypes: ['malware'],
  },
  {
    key: 'communicates',
    sentence: 'When it communicates with',
    verb: 'communicating with',
    value: 'entities',
    valueTypes: ['Infrastructure', 'Domain-Name', 'IPv4-Addr', 'Url'],
    build: { kind: 'linked', relationships: ['communicates-with', 'beacons-to'], direction: 'incoming' },
    appliesTo: ['Malware'],
    pirTypes: ['malware'],
  },
  {
    key: 'variant-of',
    sentence: 'When it is a variant of',
    verb: 'variants of',
    value: 'entities',
    valueTypes: ['Malware'],
    build: { kind: 'linked', relationships: ['variant-of'], direction: 'incoming' },
    appliesTo: ['Malware'],
    pirTypes: ['malware'],
  },
  {
    key: 'exploits',
    sentence: 'When it exploits',
    verb: 'exploiting',
    value: 'entities',
    valueTypes: ['Vulnerability'],
    build: { kind: 'linked', relationships: ['exploits'], direction: 'incoming' },
    appliesTo: ['Malware'],
    pirTypes: ['malware'],
  },
  {
    key: 'authored-by',
    sentence: 'When it is authored by',
    verb: 'authored by',
    value: 'entities',
    valueTypes: ATTRIBUTION_TYPES,
    build: { kind: 'linked', relationships: ['authored-by'], direction: 'incoming' },
    appliesTo: ['Malware'],
    pirTypes: ['malware'],
  },
  {
    key: 'capability',
    sentence: 'When it has the capability',
    verb: 'capable of',
    value: 'vocabulary',
    vocabularyField: 'capabilities',
    build: entityFilter('capabilities'),
    appliesTo: ['Malware'],
    pirTypes: ['malware'],
  },
  // vulnerability
  {
    key: 'affects',
    sentence: 'When it affects',
    verb: 'affecting',
    value: 'entities',
    valueTypes: ['Software'],
    build: { kind: 'linked', relationships: ['has'], direction: 'outgoing' },
    appliesTo: ['Vulnerability'],
    pirTypes: ['vulnerability'],
  },
  {
    key: 'affects-product',
    sentence: 'When it affects any version of',
    verb: 'affecting any version of',
    value: 'text', // product names
    build: { kind: 'linkedViaFilter', relationships: ['has'], direction: 'outgoing', anchorType: 'Software', anchorKey: 'x_opencti_product' },
    appliesTo: ['Vulnerability'],
    pirTypes: ['vulnerability'],
  },
  {
    key: 'kev',
    sentence: 'When it is in CISA KEV',
    verb: 'in CISA KEV',
    value: 'none',
    build: {
      kind: 'fixedFilter',
      filters: { mode: 'and', filters: [{ key: 'x_opencti_cisa_kev', values: ['true'], operator: 'eq', mode: 'or' }], filterGroups: [] },
    },
    appliesTo: ['Vulnerability'],
    pirTypes: ['vulnerability'],
  },
  {
    key: 'cvss',
    sentence: 'When its CVSS score is at least',
    verb: 'with CVSS {v} or higher',
    value: 'number',
    build: entityFilter('x_opencti_cvss_base_score', 'gte'),
    appliesTo: ['Vulnerability'],
    pirTypes: ['vulnerability'],
  },
  {
    key: 'epss',
    sentence: 'When its EPSS score is at least',
    verb: 'with EPSS {v} or higher',
    value: 'number',
    build: entityFilter('x_opencti_epss_score', 'gte'),
    appliesTo: ['Vulnerability'],
    pirTypes: ['vulnerability'],
  },
  {
    key: 'exploited-by',
    sentence: 'When it is exploited by',
    verb: 'exploited by',
    value: 'entitiesOrType',
    valueTypes: ['Malware'],
    build: { kind: 'linked', relationships: ['exploits'], direction: 'outgoing' },
    appliesTo: ['Vulnerability'],
    pirTypes: ['vulnerability'],
  },
  {
    key: 'targeted-by',
    sentence: 'When it is targeted by',
    verb: 'targeted by',
    value: 'entitiesOrType',
    valueTypes: ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Campaign', 'Malware'],
    build: { kind: 'linked', relationships: ['targets'], direction: 'outgoing' },
    appliesTo: ['Vulnerability'],
    pirTypes: ['vulnerability'],
  },
  // credential
  {
    key: 'in-domains',
    sentence: 'When it is in the email domains',
    verb: 'in',
    value: 'text', // domains, for example acme.com
    build: { kind: 'domains' },
    appliesTo: CREDENTIAL_FLAGS,
    pirTypes: ['credential'],
  },
  {
    key: 'data-leak',
    sentence: 'When it is exposed in a data leak',
    verb: 'exposed in a data leak',
    value: 'none',
    build: {
      kind: 'containerFixed',
      filters: {
        mode: 'and',
        filters: [
          { key: 'entity_type', values: ['Case-Incident'], operator: 'eq', mode: 'or' },
          { key: 'response_types', values: ['data-leak'], operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      },
    },
    appliesTo: CREDENTIAL_FLAGS,
    pirTypes: ['credential'],
  },
  {
    key: 'account-type',
    sentence: 'When its account type is',
    verb: 'of type',
    value: 'vocabulary',
    vocabularyField: 'account_type',
    build: entityFilter('account_type'),
    appliesTo: ['User-Account'],
    pirTypes: ['credential'],
  },
];

const appliesToFlags = (rule: IrPresetRule, flags: string[]) => rule.appliesTo === 'any'
  ? flags.length > 0
  : rule.appliesTo.some((type) => flags.includes(type));

// Rules offered for a PIR type: its own and the shared ones, narrowed to the flagged types.
// Threat custom offers every rule that fits the chosen flags, whatever the type of the rule.
export const rulesForType = (pirType: IrPirType, flags: string[]): IrPresetRule[] => IR_PRESET_RULES.filter((rule) => {
  if (rule.key === ADVANCED_RULE_KEY) return false; // offered on its own, below the rules of the menus
  if (!appliesToFlags(rule, flags)) return false;
  if (pirType === 'threat_custom') return true;
  return rule.pirTypes === 'all' || rule.pirTypes.includes(pirType);
});

// Inside a group a keywords rule is not possible: groups pick entities, not text matches.
export const rulesForGroup = (pirType: IrPirType, flags: string[]): IrPresetRule[] => rulesForType(pirType, flags)
  .filter((rule) => rule.build.kind !== 'keywords');

export const getRule = (key: string): IrPresetRule => {
  const rule = IR_PRESET_RULES.find((r) => r.key === key);
  if (!rule) throw new Error(`Unknown preset rule: ${key}`);
  return rule;
};
