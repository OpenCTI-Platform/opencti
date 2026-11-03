import type { ChipEntity, IconName } from '@filigran/design-system';
import type { SchemaCategory, SchemaType, ToggleableCategory } from '../../data/schemaTypes';

export interface CategoryMeta {
  label: string;
  description: string;
}

export const CATEGORY_META: Record<SchemaCategory, CategoryMeta> = {
  SDO: { label: 'SDO', description: 'Domain objects' },
  SCO: { label: 'SCO', description: 'Cyber observables' },
  SRO: { label: 'SRO', description: 'Relationships' },
  Meta: { label: 'Meta', description: 'Meta objects' },
  Internal: { label: 'Internal', description: 'Platform internals' },
  Abstract: { label: 'Abstract', description: 'Abstract roots' },
};

export const TOGGLEABLE_CATEGORIES: ToggleableCategory[] = ['SDO', 'SCO', 'SRO', 'Meta', 'Internal'];

export const DEFAULT_ENABLED_CATEGORIES: Record<ToggleableCategory, boolean> = {
  SDO: true,
  SCO: true,
  SRO: true,
  Meta: true,
  Internal: false,
};

// Same families as opencti-front (src/utils/Colors.ts, itemEntity), so a type has the colour it has in the platform.
const ENTITY_FAMILY: Record<string, ChipEntity> = {
  Report: 'analyses',
  Grouping: 'analyses',
  'Malware-Analysis': 'analyses',
  Note: 'analyses',
  'External-Reference': 'analyses',
  'Case-Incident': 'cases',
  'Case-Rfi': 'cases',
  'Case-Rft': 'cases',
  Task: 'cases',
  Feedback: 'cases',
  Incident: 'events',
  'Observed-Data': 'events',
  'stix-sighting-relationship': 'events',
  Indicator: 'observations',
  Infrastructure: 'observations',
  Opinion: 'observations',
  Artifact: 'observations',
  'Threat-Actor': 'all-threats',
  'Threat-Actor-Group': 'all-threats',
  'Threat-Actor-Individual': 'all-threats',
  'Intrusion-Set': 'all-threats',
  Campaign: 'all-threats',
  Malware: 'arsenal',
  Channel: 'arsenal',
  Tool: 'arsenal',
  Vulnerability: 'arsenal',
  SecurityPlatform: 'arsenal',
  'Attack-Pattern': 'techniques',
  Narrative: 'techniques',
  'Course-Of-Action': 'techniques',
  'Data-Component': 'techniques',
  'Data-Source': 'techniques',
  Language: 'techniques',
  Sector: 'victimology',
  Event: 'victimology',
  Organization: 'victimology',
  System: 'victimology',
  Individual: 'victimology',
  Region: 'location',
  Country: 'location',
  'Administrative-Area': 'location',
  City: 'location',
  Position: 'location',
};

/** Observables share one family in OpenCTI, whatever their type. */
export const entityFamily = (type: SchemaType): ChipEntity | undefined => ENTITY_FAMILY[type.id]
  ?? (type.category === 'SCO' ? 'observations' : undefined);

// Types outside any family: the design system has no category palette, so they take neutral roles.
const NEUTRAL_COLOR: Record<SchemaCategory, string> = {
  SDO: 'var(--icon-default)',
  SCO: 'var(--color-entities-observations)',
  SRO: 'var(--icon-subtle)',
  Meta: 'var(--icon-subtle)',
  Internal: 'var(--icon-disabled)',
  Abstract: 'var(--icon-disabled)',
};

/** A class-safe key for the colour: the family when there is one, the category otherwise. */
export const typeTone = (type: SchemaType) => entityFamily(type) ?? `category-${type.category.toLowerCase()}`;

export const typeColor = (type: SchemaType) => {
  const family = entityFamily(type);
  return family ? `var(--color-entities-${family})` : NEUTRAL_COLOR[type.category];
};

const TYPE_ICON: Record<string, IconName> = {
  Malware: 'custom/malware',
  'Intrusion-Set': 'custom/intrusion-set',
  'Attack-Pattern': 'custom/attack-pattern',
  'Course-Of-Action': 'custom/course-of-action',
  Infrastructure: 'custom/infrastructure',
  'Threat-Actor-Individual': 'custom/threat-actor-individual',
  City: 'custom/city',
  'Case-Incident': 'custom/case-incident',
  'Case-Rfi': 'custom/case-rfi',
  'Case-Rft': 'custom/case-rft',
  SecurityPlatform: 'custom/security-platforms',
  Sector: 'custom/target',
};

export const typeIcon = (type: SchemaType): IconName => {
  if (type.kind === 'relationship') return 'custom/relationship';
  if (type.isAbstract) return 'layers-2';
  return TYPE_ICON[type.id] ?? 'box';
};
