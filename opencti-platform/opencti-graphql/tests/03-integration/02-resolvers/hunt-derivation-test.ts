import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';

const SIGMA_RULE = `title: Hunt derivation test rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
`;

const DERIVED = gql`
  query HuntDerivedContent($entityId: ID!) {
    huntDerivedContent(entityId: $entityId) {
      entity { id entity_type relation }
      suggested_type
      sources { id entity_type relation }
      targets { id }
      elements { id entity_type value_types source_ids }
      elements_truncated
      unsupported_count
      techniques { id x_mitre_id }
      rules { id pattern_type pattern technique_ids }
    }
  }
`;

const ids: { type: string; id: string }[] = [];
const create = async (mutation: string, field: string, input: Record<string, unknown>, type: string) => {
  const result = await queryAsAdminWithSuccess({ query: gql(mutation), variables: { input } });
  const id = (result.data as Record<string, { id: string }>)[field].id;
  ids.push({ type, id });
  return id;
};
const addIndicator = (input: Record<string, unknown>) => create(
  'mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }',
  'indicatorAdd',
  input,
  'Indicator',
);
const relate = (fromId: string, toId: string, relationship_type: string) => create(
  'mutation RelationAdd($input: StixCoreRelationshipAddInput!) { stixCoreRelationshipAdd(input: $input) { id } }',
  'stixCoreRelationshipAdd',
  { fromId, toId, relationship_type },
  'relationship',
);

describe('Hunt derived content ("Hunt this")', () => {
  let intrusionSetId: string;
  let malwareId: string;
  let campaignId: string;
  let techniqueId: string;
  let lonelyTechniqueId: string;
  let ipIndicatorId: string;
  let domainIndicatorId: string;
  let fileIndicatorId: string;
  let redIndicatorId: string;
  let sigmaIndicatorId: string;
  let reportId: string;

  beforeAll(async () => {
    intrusionSetId = await create('mutation IntrusionSetAdd($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) { id } }', 'intrusionSetAdd', { name: 'Hunt derivation test intrusion set' }, 'Intrusion-Set');
    malwareId = await create('mutation MalwareAdd($input: MalwareAddInput!) { malwareAdd(input: $input) { id } }', 'malwareAdd', { name: 'Hunt derivation test malware', is_family: true }, 'Malware');
    campaignId = await create('mutation CampaignAdd($input: CampaignAddInput!) { campaignAdd(input: $input) { id } }', 'campaignAdd', { name: 'Hunt derivation test campaign' }, 'Campaign');
    techniqueId = await create('mutation AttackPatternAdd($input: AttackPatternAddInput!) { attackPatternAdd(input: $input) { id } }', 'attackPatternAdd', { name: 'Hunt derivation test technique', x_mitre_id: 'T9901' }, 'Attack-Pattern');
    lonelyTechniqueId = await create('mutation AttackPatternAdd($input: AttackPatternAddInput!) { attackPatternAdd(input: $input) { id } }', 'attackPatternAdd', { name: 'Hunt derivation test lonely technique', x_mitre_id: 'T9902' }, 'Attack-Pattern');
    ipIndicatorId = await addIndicator({ name: 'Hunt derivation test IP', pattern: "[ipv4-addr:value = '198.51.100.81']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' });
    domainIndicatorId = await addIndicator({ name: 'Hunt derivation test domain', pattern: "[domain-name:value = 'derivation-test.example.com']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' });
    fileIndicatorId = await addIndicator({ name: 'Hunt derivation test file', pattern: "[file:hashes.'SHA-256' = '0d2f4a1bb1c3a6e0f7c2a3a1d9e8b7c6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0']", pattern_type: 'stix', x_opencti_main_observable_type: 'StixFile' });
    redIndicatorId = await addIndicator({ name: 'Hunt derivation test red IP', pattern: "[ipv4-addr:value = '198.51.100.82']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr', objectMarking: [MARKING_TLP_RED] });
    sigmaIndicatorId = await addIndicator({ name: 'Hunt derivation test Sigma rule', pattern: SIGMA_RULE, pattern_type: 'sigma', x_opencti_main_observable_type: 'Unknown' });
    // The intrusion set: one indicator of its own, a malware it uses with two, a campaign attributed to it with one
    await relate(ipIndicatorId, intrusionSetId, 'indicates');
    await relate(redIndicatorId, intrusionSetId, 'indicates');
    await relate(intrusionSetId, malwareId, 'uses');
    await relate(domainIndicatorId, malwareId, 'indicates');
    await relate(fileIndicatorId, malwareId, 'indicates');
    await relate(campaignId, intrusionSetId, 'attributed-to');
    await relate(ipIndicatorId, campaignId, 'indicates');
    // The technique it uses, detected by a Sigma rule, as the defense matrix links them
    await relate(intrusionSetId, techniqueId, 'uses');
    await relate(sigmaIndicatorId, techniqueId, 'indicates');
    reportId = await create('mutation ReportAdd($input: ReportAddInput!) { reportAdd(input: $input) { id } }', 'reportAdd', {
      name: 'Hunt derivation test report',
      published: '2026-10-01T00:00:00.000Z',
      objects: [intrusionSetId, techniqueId, domainIndicatorId, sigmaIndicatorId],
    }, 'Report');
  });

  afterAll(async () => {
    const reversed = [...ids].reverse();
    for (let index = 0; index < reversed.length; index += 1) {
      const { type, id } = reversed[index];
      if (type === 'relationship') {
        await queryAsAdmin({ query: gql`mutation RelationDelete($id: ID!) { stixCoreRelationshipEdit(id: $id) { delete } }`, variables: { id } });
      } else if (type === 'Indicator') {
        await queryAsAdmin({ query: gql`mutation IndicatorDelete($id: ID!) { indicatorDelete(id: $id) }`, variables: { id } });
      } else {
        await queryAsAdmin({ query: gql`mutation ObjectDelete($id: ID!) { stixDomainObjectEdit(id: $id) { delete } }`, variables: { id } });
      }
    }
  });

  it('should derive the indicators of a threat, of its malware and of the threats attributed to it', async () => {
    const result = await queryAsAdminWithSuccess({ query: DERIVED, variables: { entityId: intrusionSetId } });
    const derived = result.data?.huntDerivedContent;
    expect(derived.entity).toEqual({ id: intrusionSetId, entity_type: 'Intrusion-Set', relation: 'self' });
    expect(derived.suggested_type).toEqual('indicators');
    expect(derived.sources).toEqual(expect.arrayContaining([
      { id: intrusionSetId, entity_type: 'Intrusion-Set', relation: 'self' },
      { id: malwareId, entity_type: 'Malware', relation: 'uses' },
      { id: campaignId, entity_type: 'Campaign', relation: 'attributed' },
    ]));
    expect(derived.sources).toHaveLength(3);
    expect(derived.targets.map(({ id }: { id: string }) => id).sort()).toEqual([intrusionSetId, malwareId, campaignId].sort());
    type Element = { id: string; value_types: string[]; source_ids: string[] };
    const byId = new Map<string, Element>(derived.elements.map((element: Element) => [element.id, element]));
    expect(Array.from(byId.keys()).sort()).toEqual([ipIndicatorId, domainIndicatorId, fileIndicatorId, redIndicatorId].sort());
    expect(byId.get(ipIndicatorId)?.value_types).toEqual(['IPv4-Addr']);
    expect(byId.get(ipIndicatorId)?.source_ids.sort()).toEqual([intrusionSetId, campaignId].sort());
    expect(byId.get(domainIndicatorId)).toMatchObject({ value_types: ['Domain-Name'], source_ids: [malwareId] });
    expect(byId.get(fileIndicatorId)).toMatchObject({ value_types: ['StixFile'], source_ids: [malwareId] });
    expect(derived.techniques).toEqual([{ id: techniqueId, x_mitre_id: 'T9901' }]);
    // String attributes are stored trimmed
    expect(derived.rules).toEqual([{ id: sigmaIndicatorId, pattern_type: 'sigma', pattern: SIGMA_RULE.trim(), technique_ids: [techniqueId] }]);
    expect(derived.elements_truncated).toBe(false);
  });

  it('should only derive what the user can access', async () => {
    const result = await queryAsUserWithSuccess(USER_EDITOR, { query: DERIVED, variables: { entityId: intrusionSetId } });
    const elementIds = result.data?.huntDerivedContent.elements.map(({ id }: { id: string }) => id);
    expect(elementIds).not.toContain(redIndicatorId);
    expect(elementIds).toContain(ipIndicatorId);
  });

  it('should propose the detection rules of a technique', async () => {
    const result = await queryAsAdminWithSuccess({ query: DERIVED, variables: { entityId: techniqueId } });
    const derived = result.data?.huntDerivedContent;
    expect(derived.suggested_type).toEqual('telemetry');
    expect(derived.elements).toEqual([]);
    expect(derived.sources).toEqual([]);
    expect(derived.rules.map(({ id }: { id: string }) => id)).toEqual([sigmaIndicatorId]);
  });

  it('should derive what a report contains', async () => {
    const result = await queryAsAdminWithSuccess({ query: DERIVED, variables: { entityId: reportId } });
    const derived = result.data?.huntDerivedContent;
    expect(derived.suggested_type).toEqual('indicators');
    expect(derived.sources).toEqual([{ id: reportId, entity_type: 'Report', relation: 'self' }]);
    expect(derived.targets.map(({ id }: { id: string }) => id)).toEqual([intrusionSetId]);
    expect(derived.elements.map(({ id }: { id: string }) => id)).toEqual([domainIndicatorId]);
    expect(derived.techniques.map(({ id }: { id: string }) => id)).toEqual([techniqueId]);
    expect(derived.rules).toEqual([expect.objectContaining({ id: sigmaIndicatorId, technique_ids: [techniqueId] })]);
    expect(derived.unsupported_count).toEqual(0);
  });

  it('should derive an indicator itself, and say when there is nothing to hunt', async () => {
    const sigma = await queryAsAdminWithSuccess({ query: DERIVED, variables: { entityId: sigmaIndicatorId } });
    expect(sigma.data?.huntDerivedContent).toMatchObject({ suggested_type: 'telemetry', elements: [], techniques: [{ id: techniqueId }] });
    expect(sigma.data?.huntDerivedContent.rules.map(({ id }: { id: string }) => id)).toEqual([sigmaIndicatorId]);
    const ip = await queryAsAdminWithSuccess({ query: DERIVED, variables: { entityId: ipIndicatorId } });
    expect(ip.data?.huntDerivedContent).toMatchObject({ suggested_type: 'indicators', elements: [{ id: ipIndicatorId, value_types: ['IPv4-Addr'] }] });
    const lonely = await queryAsAdminWithSuccess({ query: DERIVED, variables: { entityId: lonelyTechniqueId } });
    expect(lonely.data?.huntDerivedContent).toMatchObject({ suggested_type: null, elements: [], rules: [] });
  });
});
