import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { normalizeSchema } from '../data/normalizeSchema';
import type { NormalizedSchema, RawAttribute, RawSchema } from '../data/schemaTypes';

const attribute = (name: string, isStix = true): RawAttribute => ({ name, type: 'string', label: name, multiple: false, mandatory: 'no', isStix });

const type = (id: string, attributes: string[], isRelationship = false) => ({
  id,
  type: isRelationship ? 'relationship' as const : 'entity' as const,
  data: { label: id, isRelationship, attributes: attributes.map((name) => attribute(name)) },
});

const isA = (child: string, parent: string) => ({ id: `inheritance_${child}_${parent}`, source: child, target: parent, label: 'is-a' });

/** A relation slot plus its target group, as generate-graph.ts writes them. */
const relation = (source: string, name: string, targets: string[], kind: 'relationship' | 'ref' = 'relationship') => {
  const slot = `${source}_${name}`;
  return {
    nodes: [
      { id: slot, type: 'relationship' as const, data: { label: name, isRelationship: true, attributes: [], stixType: kind === 'ref' ? name : 'builtin', isRefAttribute: kind === 'ref' } },
      { id: `${slot}_targets`, type: 'target-group' as const, data: { label: 'Targets', items: targets.map((label) => ({ label, isRelationship: false })), isDuplicate: true } },
    ],
    edges: [
      { id: `${source}->${slot}`, source, target: slot, label: '' },
      { id: `${slot}->${slot}_targets`, source: slot, target: `${slot}_targets`, label: '' },
    ],
  };
};

/**
 * Tiny OpenCTI-like hierarchy:
 * Stix-Domain-Object > Malware, Tool, Threat-Actor > Threat-Actor-Group, Threat-Actor-Individual, Sector, Country, Region, City
 */
export const buildFixtureSchema = (): NormalizedSchema => {
  const relations = [
    relation('Malware', 'uses', ['Tool', 'Malware']),
    relation('Malware', 'targets', ['Sector', 'Country', 'Region', 'City', 'Threat-Actor-Group']),
    relation('Malware', 'createdBy', ['Threat-Actor-Group'], 'ref'),
    relation('Threat-Actor-Group', 'uses', ['Malware', 'Tool']),
    relation('Tool', 'attributed-to', ['Threat-Actor']),
    relation('Tool', 'related-to', ['Malware']),
  ];
  const raw: RawSchema = {
    nodes: [
      type('Stix-Domain-Object', ['id', 'name']),
      type('Threat-Actor', ['id', 'name', 'aliases']),
      ...['Malware', 'Tool', 'Sector', 'Country', 'Region', 'City', 'Threat-Actor-Group', 'Threat-Actor-Individual']
        .map((id) => type(id, ['id', 'name', ...(id === 'Malware' ? ['is_family'] : []), ...(id.startsWith('Threat-Actor-') ? ['aliases'] : [])])),
      type('stix-core-relationship', ['id'], true),
      type('uses', ['id', 'start_time'], true),
      type('targets', ['id'], true),
      type('attributed-to', ['id'], true),
      type('related-to', ['id'], true),
      ...relations.flatMap((entry) => entry.nodes),
    ],
    edges: [
      ...['Malware', 'Tool', 'Threat-Actor', 'Sector', 'Country', 'Region', 'City'].map((id) => isA(id, 'Stix-Domain-Object')),
      isA('Threat-Actor-Group', 'Threat-Actor'),
      isA('Threat-Actor-Individual', 'Threat-Actor'),
      ...['uses', 'targets', 'attributed-to', 'related-to'].map((id) => isA(id, 'stix-core-relationship')),
      ...relations.flatMap((entry) => entry.edges),
    ],
  };
  return normalizeSchema(raw);
};

let realSchema: NormalizedSchema | null = null;

/** The schema.json checked into public/, normalized once per test run. */
export const loadRealSchema = (): NormalizedSchema => {
  if (!realSchema) {
    const file = fileURLToPath(new URL('../../public/schema.json', import.meta.url));
    realSchema = normalizeSchema(JSON.parse(readFileSync(file, 'utf8')) as RawSchema);
  }
  return realSchema;
};
