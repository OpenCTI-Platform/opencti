import { describe, expect, it } from 'vitest';
// the organization module registers its standard id contribution on import (identity_class + name)
import '../../../src/modules/organization/organization';
import { chunkOperationRootField, producerStandardId, resolveProducerIds } from '../../../src/manager/chunkIntakeProducers';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import type { ChunkOperation } from '../../../src/graphql/chunk-executor';

const LABEL = 'mutation LabelAdd($input: LabelAddInput!) { labelAdd(input: $input) { id } }';
const EXT_REF = 'mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) { externalReferenceAdd(input: $input) { id } }';
const KCP = 'mutation KillChainPhaseAdd($input: KillChainPhaseAddInput!) { killChainPhaseAdd(input: $input) { id } }';
const ORG = 'mutation IdentityAdd($input: OrganizationAddInput!) { organizationAdd(input: $input) { id } }';
const IDENTITY = 'mutation IdentityAdd($input: IdentityAddInput!) { identityAdd(input: $input) { id } }';
const INDICATOR = 'mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }';

const producer = (query: string, input: Record<string, any>, echo = 'echo--1'): ChunkOperation => ({ query, variables: { input }, echo_id: echo });

describe('chunk intake producers resolved by standard id', () => {
  it('reads the root mutation field, by operation name when several are present', () => {
    expect(chunkOperationRootField({ query: LABEL })).toBe('labelAdd');
    expect(chunkOperationRootField({ query: `${LABEL} ${KCP}`, operationName: 'KillChainPhaseAdd' })).toBe('killChainPhaseAdd');
    expect(chunkOperationRootField({ query: 'query Q { me { id } }' })).toBeNull();
    expect(chunkOperationRootField({ query: 'not graphql {' })).toBeNull();
  });

  it('gives a label the id the platform computes, case and spaces normalized', () => {
    const id = producerStandardId(producer(LABEL, { value: '  Malware ', color: '#ff0000' }));
    expect(id).toBe(generateStandardId(ENTITY_TYPE_LABEL, { value: 'malware' }));
    expect(id?.startsWith('label--')).toBe(true);
  });

  it('gives an external reference its id by url, or by source name and external id', () => {
    const byUrl = producerStandardId(producer(EXT_REF, { source_name: 'mitre-attack', url: 'https://attack.mitre.org/techniques/T1059', external_id: 'T1059', description: null }));
    expect(byUrl).toBe(generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, { url: 'https://attack.mitre.org/techniques/T1059' }));
    const byExternalId = producerStandardId(producer(EXT_REF, { source_name: 'capec', url: null, external_id: 'CAPEC-1', description: null }));
    expect(byExternalId).toBe(generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, { source_name: 'capec', external_id: 'CAPEC-1' }));
    expect(byUrl).not.toBe(byExternalId);
  });

  it('gives a kill chain phase its id from the chain and phase names', () => {
    const id = producerStandardId(producer(KCP, { kill_chain_name: 'mitre-attack', phase_name: 'execution', x_opencti_order: 0 }));
    expect(id).toBe(generateStandardId(ENTITY_TYPE_KILL_CHAIN_PHASE, { kill_chain_name: 'mitre-attack', phase_name: 'execution' }));
  });

  it('fixes the identity class the domain adds for identities created by name', () => {
    const org = producerStandardId(producer(ORG, { name: 'The MITRE Corporation', description: '' }));
    expect(org).toBe(generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, { name: 'The MITRE Corporation', identity_class: 'organization' }));
    const sector = producerStandardId(producer(IDENTITY, { type: 'Sector', name: 'Energy' }));
    expect(sector).toBe(generateStandardId(ENTITY_TYPE_IDENTITY_SECTOR, { name: 'Energy', identity_class: 'class' }));
    expect(producerStandardId(producer(IDENTITY, { name: 'no type' }))).toBeNull();
  });

  it('declines what it cannot resolve: unknown mutation, missing input, input the platform refuses', () => {
    expect(producerStandardId(producer(INDICATOR, { name: 'x', pattern: 'y' }))).toBeNull();
    expect(producerStandardId({ query: LABEL, echo_id: 'echo--2' })).toBeNull();
    expect(producerStandardId({ query: LABEL, variables: { input: ['not', 'an', 'object'] }, echo_id: 'echo--3' })).toBeNull();
    // an external reference with a source name only has no id-contributing way
    expect(producerStandardId(producer(EXT_REF, { source_name: 'only', url: null, external_id: null }))).toBeNull();
  });

  it('splits a chunk into producers resolved up front and producers to execute first', () => {
    const label = producer(LABEL, { value: 'apt' }, 'echo--label');
    const orphan = producer(EXT_REF, { source_name: 'only', url: null, external_id: null }, 'echo--orphan');
    const consumer: ChunkOperation = { query: INDICATOR, variables: { input: { name: 'i', objectLabel: ['echo--label'], externalReferences: ['echo--orphan'] } }, object_id: 'indicator--1' };
    const { resolved, unresolved } = resolveProducerIds([label, orphan, consumer]);
    expect(Array.from(resolved.keys())).toEqual(['echo--label']);
    expect(resolved.get('echo--label')).toBe(generateStandardId(ENTITY_TYPE_LABEL, { value: 'apt' }));
    expect(unresolved).toEqual([orphan]);
  });
});
