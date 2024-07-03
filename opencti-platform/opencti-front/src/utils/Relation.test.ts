import { describe, it, expect } from 'vitest';
import { getRelationsFromOneEntityToAny, resolveRelationsTypes } from './Relation';
import { type SchemaType } from './hooks/useAuth';

// Subset of schemas to tests utilities
// Feel free to add more
const testSchema: SchemaType = {
  schemaRelationsTypesMapping: new Map([
    ['Attack-Pattern_Attack-Pattern', ['subtechnique-of']],
    ['Attack-Pattern_City', ['targets']],
    ['Attack-Pattern_Administrative-Area', ['targets']],
    ['Attack-Pattern_Country', ['targets']],
    ['Campaign_Attack-Pattern', ['uses']],
    ['Campaign_Channel', ['uses']],
    ['Campaign_City', ['originates-from', 'targets']],
    ['Campaign_Administrative-Area', ['originates-from', 'targets']],
    ['Campaign_Country', ['targets', 'originates-from']],
    ['Course-Of-Action_Attack-Pattern', ['mitigates']],
  ]),
  filterKeysSchema: new Map([
    ['Basic-Object', new Map()],
    ['Container', new Map()],
    ['Attack-Pattern', new Map()],
    ['Campaign', new Map()]]),
  schemaRelationsRefTypesMapping: new Map([
    ['*_Case-Incident', [{ name: 'createdBy', toTypes: ['Individual'] }]],
    ['*_Case-Rfi', [{ name: 'createdBy', toTypes: ['Individual'] }]],
    ['*_Case-Rft', [{ name: 'createdBy', toTypes: ['Individual'] }]],
  ]),
  scos: [
    { id: 'Artifact', label: 'Artifact' },
    { id: 'Autonomous-System', label: 'Autonomous-System' },
    { id: 'Bank-Account', label: 'Bank-Account' },
    { id: 'Credential', label: 'Credential' },
    { id: 'Cryptocurrency-Wallet', label: 'Cryptocurrency-Wallet' },
    { id: 'Cryptographic-Key', label: 'Cryptographic-Key' },
    { id: 'Directory', label: 'Directory' },
    { id: 'Domain-Name', label: 'Domain-Name' },
  ],
  sdos: [
    { id: 'Administrative-Area', label: 'Administrative-Area' },
    { id: 'Attack-Pattern', label: 'Attack-Pattern' },
    { id: 'Campaign', label: 'Campaign' },
    { id: 'Case-Incident', label: 'Case-Incident' },
    { id: 'Case-Rfi', label: 'Case-Rfi' },
    { id: 'Case-Rft', label: 'Case-Rft' },
    { id: 'Channel', label: 'Channel' },
    { id: 'City', label: 'City' },
    { id: 'Country', label: 'Country' },
    { id: 'Course-Of-Action', label: 'Course-Of-Action' },
    { id: 'Data-Component', label: 'Data-Component' },
    { id: 'Data-Source', label: 'Data-Source' },
  ],
  smos: [
    { id: 'External-Reference', label: 'External-Reference' },
    { id: 'Kill-Chain-Phase', label: 'Kill-Chain-Phase' },
    { id: 'Label', label: 'Label' },
    { id: 'Marking-Definition', label: 'Marking-Definition' },
    { id: 'Vocabulary', label: 'Vocabulary' },
  ],
  scrs: [
    { id: 'amplifies', label: 'amplifies' },
    { id: 'analysis-of', label: 'analysis-of' },
    { id: 'attributed-to', label: 'attributed-to' },
    { id: 'authored-by', label: 'authored-by' },
    { id: 'based-on', label: 'based-on' },
    { id: 'beacons-to', label: 'beacons-to' },
    { id: 'belongs-to', label: 'belongs-to' },
    { id: 'characterizes', label: 'characterizes' },
    { id: 'citizen-of', label: 'citizen-of' },
    { id: 'communicates-with', label: 'communicates-with' },
    { id: 'compromises', label: 'compromises' },
    { id: 'consists-of', label: 'consists-of' },
    { id: 'controls', label: 'controls' },
    { id: 'cooperates-with', label: 'cooperates-with' },
    { id: 'delivers', label: 'delivers' },
    { id: 'derived-from', label: 'derived-from' },
    { id: 'detects', label: 'detects' },
    { id: 'downloads', label: 'downloads' },
    { id: 'drops', label: 'drops' },
    { id: 'duplicate-of', label: 'duplicate-of' },
    { id: 'dynamic-analysis-of', label: 'dynamic-analysis-of' },
  ],
};

describe('Test schema utilities functions', () => {
  it('should get all relationType with from and to entity', () => {
    const relations = resolveRelationsTypes('Campaign', 'Administrative-Area', testSchema.schemaRelationsTypesMapping, true);
    expect(relations.length).toBe(3);

    // contains all expected values
    const matchesAll = relations.filter((relation) => { return relation === 'related-to' || relation === 'originates-from' || relation === 'targets'; });
    expect(matchesAll.length).toBe(3);
  });

  it('should get all relationType with from entity Campaign', () => {
    const result = getRelationsFromOneEntityToAny('Campaign', testSchema);
    expect(result.allPossibleRelations.length).toBe(4);
    const matchesAll = result.allPossibleRelations.filter((relation) => { return relation === 'uses' || relation === 'related-to' || relation === 'originates-from' || relation === 'targets'; });
    expect(matchesAll.length).toBe(4);

    expect(result.allRelationsToEntity.length).toBe(20);
  });

  it('should get all relationType with from entity not in list', () => {
    const result = getRelationsFromOneEntityToAny('Wrong-Stuff', testSchema);
    expect(result.allPossibleRelations.length).toBe(1);
    expect(result.allPossibleRelations[0]).toBe('related-to');
    expect(result.allRelationsToEntity.length).toBe(20);
  });
});
