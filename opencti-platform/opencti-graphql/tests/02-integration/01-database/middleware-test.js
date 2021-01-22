import * as R from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import {
  createEntity,
  createRelation,
  dayFormat,
  deleteElementById,
  distributionEntities,
  distributionRelations,
  escape,
  internalLoadById,
  listEntities,
  listRelations,
  loadById,
  loadByIdFullyResolved,
  mergeEntities,
  monthFormat,
  now,
  patchAttribute,
  prepareDate,
  querySubTypes,
  REL_CONNECTED_SUFFIX,
  sinceNowInMinutes,
  timeSeriesEntities,
  timeSeriesRelations,
  updateAttribute,
  yearFormat,
} from '../../../src/database/middleware';
import { attributeEditField, findAll as findAllAttributes } from '../../../src/domain/attribute';
import { INDEX_STIX_DOMAIN_OBJECTS, utcDate } from '../../../src/database/utils';
import { DATA_INDICES, el, elLoadByIds } from '../../../src/database/elasticSearch';
import { ADMIN_USER, sleep } from '../../utils/testQuery';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
} from '../../../src/schema/stixDomainObject';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, REL_INDEX_PREFIX } from '../../../src/schema/general';
import { RELATION_MITIGATES, RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { SYSTEM_USER } from '../../../src/domain/user';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../../../src/schema/stixCyberObservable';
import { RELATION_OBJECT_LABEL } from '../../../src/schema/stixMetaRelationship';
import { addLabel } from '../../../src/domain/label';

describe('Basic and utils', () => {
  it('should escape according to grakn needs', () => {
    expect(escape({ key: 'json' })).toEqual({ key: 'json' });
    expect(escape('simple ident')).toEqual('simple ident');
    expect(escape('grakn\\special')).toEqual('grakn\\\\special');
    expect(escape('grakn;injection')).toEqual('grakn\\;injection');
    expect(escape('grakn,injection')).toEqual('grakn\\,injection');
  });
  it('should date utils correct', () => {
    expect(utcDate().isValid()).toBeTruthy();
    expect(utcDate(now()).isValid()).toBeTruthy();
    expect(sinceNowInMinutes(now())).toEqual(0);
    // Test with specific timezone
    expect(prepareDate('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12-31T23:00:00.001');
    expect(yearFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019');
    expect(monthFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12');
    expect(dayFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12-31');
    // Test with direct utc
    expect(prepareDate('2020-02-27T08:45:39.351Z')).toEqual('2020-02-27T08:45:39.351');
    expect(yearFormat('2020-02-27T08:45:39.351Z')).toEqual('2020');
    expect(monthFormat('2020-02-27T08:45:39.351Z')).toEqual('2020-02');
    expect(dayFormat('2020-02-27T08:45:39.351Z')).toEqual('2020-02-27');
  });
});

describe('Loaders', () => {
  it('should load subTypes values', async () => {
    const stixObservableSubTypes = await querySubTypes({ type: 'Stix-Cyber-Observable' });
    expect(stixObservableSubTypes).not.toBeNull();
    expect(stixObservableSubTypes.edges.length).toEqual(26);
    const subTypeLabels = R.map((e) => e.node.label, stixObservableSubTypes.edges);
    expect(R.includes('IPv4-Addr', subTypeLabels)).toBeTruthy();
    expect(R.includes('IPv6-Addr', subTypeLabels)).toBeTruthy();
  });
});

describe('Attribute updater', () => {
  const noCacheCases = [[true], [false]];
  // TODO JRI HOW TO CHECK THE ES SCHEMA
  it.skip('should update fail for unknown attributes', async () => {
    const campaign = await elLoadByIds('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const campaignId = campaign.internal_id;
    const input = { observable_value: 'test' };
    const update = patchAttribute(ADMIN_USER, campaignId, ENTITY_TYPE_CAMPAIGN, input);
    expect(update).rejects.toThrow();
  });
  it('should update dont do anything if already the same', async () => {
    const campaign = await elLoadByIds('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const campaignId = campaign.internal_id;
    const patch = { description: 'A test campaign' };
    const update = await patchAttribute(ADMIN_USER, campaignId, ENTITY_TYPE_CAMPAIGN, patch);
    expect(update.internal_id).toEqual(campaignId);
  });
  it.each(noCacheCases)('should update date with dependencies', async (noCache) => {
    const stixId = 'campaign--92d46985-17a6-4610-8be8-cc70c82ed214';
    let campaign = await internalLoadById(stixId, { noCache });
    const campaignId = campaign.internal_id;
    expect(campaign.first_seen).toEqual('2020-02-27T08:45:43.365Z');
    const type = 'Stix-Domain-Object';
    let patch = { first_seen: '2020-02-20T08:45:43.366Z' };
    let update = await patchAttribute(ADMIN_USER, campaignId, type, patch);
    expect(update.internal_id).toEqual(campaignId);
    campaign = await internalLoadById(stixId, { noCache });
    expect(campaign.first_seen).toEqual('2020-02-20T08:45:43.366Z');
    expect(campaign.i_first_seen_day).toEqual('2020-02-20');
    expect(campaign.i_first_seen_month).toEqual('2020-02');
    expect(campaign.i_first_seen_year).toEqual('2020');
    // Value back to before
    patch = { first_seen: '2020-02-27T08:45:43.365Z' };
    update = await patchAttribute(ADMIN_USER, campaignId, type, patch);
    expect(update.internal_id).toEqual(campaignId);
    campaign = await internalLoadById(stixId, { noCache });
    expect(campaign.first_seen).toEqual('2020-02-27T08:45:43.365Z');
    expect(campaign.i_first_seen_day).toEqual('2020-02-27');
  });
  it.each(noCacheCases)('should update numeric', async (noCache) => {
    const stixId = 'relationship--efc9bbb8-e606-4fb1-83ae-d74690fd0416';
    let relation = await loadById(stixId, ABSTRACT_STIX_CORE_RELATIONSHIP, { noCache });
    const relationId = relation.internal_id;
    // expect(relation.confidence).toEqual(1);
    let patch = { confidence: 5 };
    await patchAttribute(ADMIN_USER, relationId, RELATION_MITIGATES, patch, { noCache });
    relation = await loadById(stixId, ABSTRACT_STIX_CORE_RELATIONSHIP, { noCache });
    expect(relation.confidence).toEqual(5);
    // Value back to before
    patch = { confidence: 1 };
    await patchAttribute(ADMIN_USER, relationId, RELATION_MITIGATES, patch, { noCache });
    relation = await loadById(stixId, ABSTRACT_STIX_CORE_RELATIONSHIP, { noCache });
    expect(relation.confidence).toEqual(1);
  });
  it.each(noCacheCases)('should update multivalued attribute', async (noCache) => {
    const stixId = 'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132';
    const type = 'Stix-Domain-Object';
    let identity = await internalLoadById(stixId, { noCache });
    const identityId = identity.internal_id;
    expect(identity.x_opencti_aliases.sort()).toEqual(['Computer Incident', 'Incident'].sort());
    let patch = { x_opencti_aliases: ['Computer', 'Test', 'Grakn'] };
    await patchAttribute(ADMIN_USER, identityId, type, patch);
    identity = await internalLoadById(stixId, { noCache });
    expect(identity.x_opencti_aliases.sort()).toEqual(['Computer', 'Test', 'Grakn'].sort());
    // Value back to before
    patch = { x_opencti_aliases: ['Computer Incident', 'Incident'] };
    await patchAttribute(ADMIN_USER, identityId, type, patch);
    identity = await internalLoadById(stixId, { noCache });
    expect(identity.x_opencti_aliases.sort()).toEqual(['Computer Incident', 'Incident'].sort());
  });
});

describe('Entities listing', () => {
  // const { first = 1000, after, orderBy, orderMode = 'asc', noCache = false }
  // filters part. Definition -> { key, values, fromRole, toRole }
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should list entities (noCache = %s)', async (noCache) => {
    const malwares = await listEntities(['Malware'], { noCache });
    expect(malwares).not.toBeNull();
    expect(malwares.edges.length).toEqual(2);
    const dataMap = new Map(malwares.edges.map((i) => [R.head(i.node.x_opencti_stix_ids), i.node]));
    const malware = dataMap.get('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware.grakn_id).not.toBeNull();
    expect(malware.standard_id).toEqual('malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714');
    expect(malware.created_at_month).not.toBeNull();
    expect(malware.parent_types.length).toEqual(4);
    expect(R.includes('Stix-Domain-Object', malware.parent_types)).toBeTruthy();
    expect(R.includes('Stix-Core-Object', malware.parent_types)).toBeTruthy();
    expect(R.includes('Stix-Object', malware.parent_types)).toBeTruthy();
    expect(R.includes('Basic-Object', malware.parent_types)).toBeTruthy();
    expect(malware.created).toEqual('2019-09-30T16:38:26.000Z');
    expect(malware.name).toEqual('Paradise Ransomware');
    // eslint-disable-next-line
    expect(malware._index).toEqual(INDEX_STIX_DOMAIN_OBJECTS);
  });
  it.each(noCacheCases)('should list multiple entities (noCache = %s)', async (noCache) => {
    const entities = await listEntities(['Malware', 'Organization'], { noCache });
    expect(entities).not.toBeNull();
    expect(entities.edges.length).toEqual(7); // 2 malwares + 8 organizations
    const aggregationMap = new Map(entities.edges.map((i) => [i.node.name, i.node]));
    expect(aggregationMap.get('Paradise Ransomware')).not.toBeUndefined();
    expect(aggregationMap.get('Allied Universal')).not.toBeUndefined();
    expect(aggregationMap.get('ANSSI')).not.toBeUndefined();
    expect(aggregationMap.get('France')).toBeUndefined(); // Stix organization convert to Country with OpenCTI
  });
  it.each(noCacheCases)('should list entities with basic filtering (noCache = %s)', async (noCache) => {
    const options = { first: 1, after: offsetToCursor(2), orderBy: 'created', orderMode: 'desc', noCache };
    const indicators = await listEntities(['Indicator'], options);
    expect(indicators.edges.length).toEqual(1);
    const indicator = R.head(indicators.edges).node;
    expect(indicator.name).toEqual('2a0169c72c84e6d3fa49af701fd46ee7aaf1d1d9e107798d93a6ca8df5d25957');
  });
  it.each(noCacheCases)('should list entities with search (noCache = %s)', async (noCache) => {
    let options = { search: 'xolod', noCache };
    let indicators = await listEntities(['Indicator'], options);
    expect(indicators.edges.length).toEqual(1);
    options = { search: 'location', noCache };
    indicators = await listEntities(['Indicator'], options);
    expect(indicators.edges.length).toEqual(2);
    options = { search: 'i want a location', noCache };
    indicators = await listEntities(['Indicator'], options);
    expect(indicators.edges.length).toEqual(3);
  });
  it.each(noCacheCases)('should list entities with attribute filters (noCache = %s)', async (noCache) => {
    const filters = [
      { key: 'x_mitre_id', values: ['T1369'] },
      { key: 'name', values: ['Spear phishing messages with malicious links'] },
    ];
    const options = { filters, noCache };
    const attacks = await listEntities(['Attack-Pattern'], options);
    expect(attacks).not.toBeNull();
    expect(attacks.edges.length).toEqual(1);
    expect(R.head(attacks.edges).node.standard_id).toEqual('attack-pattern--acdfc109-e0fd-5711-839b-a37ee49529b9');
    expect(R.head(attacks.edges).node.x_opencti_stix_ids).toEqual([
      'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc',
    ]);
  });
  it.each(noCacheCases)('should list multiple entities with attribute filters (noCache = %s)', async (noCache) => {
    const identity = await elLoadByIds('identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5');
    const filters = [{ key: `rel_created-by.internal_id`, values: [identity.internal_id] }];
    const options = { filters, noCache };
    const entities = await listEntities(['Attack-Pattern', 'Intrusion-Set'], options);
    expect(entities).not.toBeNull();
    expect(entities.edges.length).toEqual(3);
  });
});

describe('Relations listing', () => {
  // const { first = 1000, after, orderBy, orderMode = 'asc', noCache = false, inferred = false, forceNatural = false }
  // const { filters = [], search, fromRole, fromId, toRole, toId, fromTypes = [], toTypes = [] }
  // const { firstSeenStart, firstSeenStop, lastSeenStart, lastSeenStop, confidences = [] }
  const noCacheCases = [[true], [false]];
  // uses: { user: ROLE_FROM, usage: ROLE_TO }
  it.each(noCacheCases)('should list relations (noCache = %s)', async (noCache) => {
    const stixCoreRelationships = await listRelations('stix-core-relationship', { noCache });
    expect(stixCoreRelationships).not.toBeNull();
    expect(stixCoreRelationships.edges.length).toEqual(21);
    const stixMetaRelationships = await listRelations('stix-meta-relationship', { noCache });
    expect(stixMetaRelationships).not.toBeNull();
    expect(stixMetaRelationships.edges.length).toEqual(109);
  });
  it.each(noCacheCases)('should list relations with roles (noCache = %s)', async (noCache) => {
    const stixRelations = await listRelations('uses', { noCache, fromRole: 'uses_from', toRole: 'uses_to' });
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(3);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromRole).toEqual('uses_from');
      expect(stixRelation.toRole).toEqual('uses_to');
    }
  });
  it.each(noCacheCases)('should list relations with id option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const options = { noCache, fromId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330' };
    const thing = await internalLoadById('ab78a62f-4928-4d5a-8740-03f0af9c4330');
    const stixRelations = await listRelations('uses', options);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromId).toEqual(thing.grakn_id);
    }
  });
  it.each(noCacheCases)('should list relations with from types option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const intrusionSet = await internalLoadById('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    expect(intrusionSet.entity_type).toEqual('Intrusion-Set');
    const options = { noCache, fromId: intrusionSet.internal_id, fromTypes: ['Intrusion-Set'] };
    const stixRelations = await listRelations('targets', options);
    expect(stixRelations.edges.length).toEqual(2);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromId).toEqual(intrusionSet.internal_id);
    }
  });
  it.each(noCacheCases)('should list relations with to types option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const malware = await internalLoadById('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { noCache, fromId: malware.internal_id, toTypes: ['Attack-Pattern'] };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      // eslint-disable-next-line no-await-in-loop
      const toThing = await elLoadByIds(stixRelation.toId);
      expect(toThing.entity_type).toEqual('Attack-Pattern');
      expect(stixRelation.fromId).toEqual(malware.internal_id);
    }
  });
  it.each(noCacheCases)('should list relations with first and order filtering (noCache = %s)', async (noCache) => {
    const options = { first: 6, after: offsetToCursor(0), orderBy: 'created', orderMode: 'asc', noCache };
    const stixRelations = await listRelations('stix-core-relationship', options);
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(6);
    // Every relations must have natural ordering for from and to
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      // eslint-disable-next-line camelcase
      const { fromRole, toRole, relationship_type: relationshipType } = stixRelation;
      expect(fromRole).toEqual(`${relationshipType}_from`);
      expect(toRole).toEqual(`${relationshipType}_to`);
    }
    const relation = R.head(stixRelations.edges).node;
    expect(relation.created).toEqual('2019-04-25T20:53:08.446Z');
  });
  it.each(noCacheCases)('should list relations with relation filtering (noCache = %s)', async (noCache) => {
    let stixRelations = await listRelations('uses', { noCache });
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(3);
    // Filter the list through relation filter
    // [Malware: Paradise Ransomware] ---- (user) ---- <uses> ---- (usage) ---- [Attack pattern: Spear phishing messages with text only]
    //                                                   |
    //                                             (characterize)
    //                                                   |
    //                                              < indicates >
    //                                                   |
    //                                               (indicator)
    //                                                   |
    //                                     [Indicator: www.xolod-teplo.ru]
    const indicator = await elLoadByIds('indicator--10e9a46e-7edb-496b-a167-e27ea3ed0079');
    const indicatorId = indicator.internal_id; // indicator -> www.xolod-teplo.ru
    const relationFilter = {
      relation: 'indicates',
      fromRole: 'indicates_to',
      toRole: 'indicates_from',
      id: indicatorId,
    };
    const options = { noCache, relationFilter };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
    const relation = R.head(stixRelations.edges).node;
    expect(relation.x_opencti_stix_ids).toEqual(['relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de']);
    expect(relation.fromRole).toEqual('uses_from');
    expect(relation.toRole).toEqual('uses_to');
    expect(relation.created).toEqual('2020-03-01T14:05:16.797Z');
  });
  it.each(noCacheCases)('should list relations with relation filtering on report (noCache = %s)', async (noCache) => {
    const report = await elLoadByIds('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const relationFilter = {
      relation: 'object',
      fromRole: 'object_to',
      toRole: 'object_from',
      id: report.internal_id,
    };
    const args = { noCache, relationFilter };
    const stixRelations = await listRelations('stix-core-relationship', args);
    // TODO Ask Julien
    expect(stixRelations.edges.length).toEqual(11);
    const relation = await elLoadByIds('relationship--b703f822-f6f0-4d96-9c9b-3fc0bb61e69c');
    const argsWithRelationId = {
      noCache,
      relationFilter: R.assoc('relationId', relation.internal_id, relationFilter),
    };
    const stixRelationsWithInternalId = await listRelations('stix-core-relationship', argsWithRelationId);
    expect(stixRelationsWithInternalId.edges.length).toEqual(1);
  });
  it.each(noCacheCases)('should list relations with to attribute filtering (noCache = %s)', async (noCache) => {
    const options = { orderBy: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`, orderMode: 'asc', noCache };
    const stixRelations = await listRelations('uses', options);
    // TODO Fix that test
    expect(stixRelations).not.toBeNull();
  });
  it.each(noCacheCases)('should list relations with search (noCache = %s)', async (noCache) => {
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { noCache, fromId: malware.internal_id, search: 'Spear phishing' };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    const relTargets = await Promise.all(R.map((s) => elLoadByIds(s.node.toId), stixRelations.edges));
    for (let index = 0; index < relTargets.length; index += 1) {
      const target = relTargets[index];
      expect(target.name).toEqual(expect.stringContaining('Spear phishing'));
    }
  });
  it.each(noCacheCases)('should list relations start time (noCache = %s)', async (noCache) => {
    // Uses relations first seen
    // 0 = "2020-02-29T23:00:00.000Z" | 1 = "2020-02-29T23:00:00.000Z" | 2 = "2020-02-28T23:00:00.000Z"
    const options = { noCache, startTimeStart: '2020-02-29T22:00:00.000Z', stopTimeStop: '2020-02-29T23:30:00.000Z' };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
  });
  it.each(noCacheCases)('should list relations stop time (noCache = %s)', async (noCache) => {
    // Uses relations last seen
    // 0 = "2020-02-29T23:00:00.000Z" | 1 = "2020-02-29T23:00:00.000Z" | 2 = "2020-02-29T23:00:00.000Z"
    let options = { noCache, startTimeStart: '2020-02-29T23:00:00.000Z', stopTimeStop: '2020-02-29T23:00:00.000Z' };
    let stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(0);
    options = { noCache, startTimeStart: '2020-02-29T22:59:59.000Z', stopTimeStop: '2020-02-29T23:00:01.000Z' };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
  });
  it.each(noCacheCases)('should list relations with confidence (noCache = %s)', async (noCache) => {
    const options = { noCache, confidences: [20] };
    const stixRelations = await listRelations('indicates', options);
    expect(stixRelations.edges.length).toEqual(2);
  });
  it.skip('should list relations with filters (noCache = %s)', async (noCache) => {
    let filters = [{ key: 'connections', nested: [{ key: 'name', values: ['malicious'], operator: 'wildcard' }] }];
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    let options = { noCache, fromId: malware.internal_id, filters };
    let stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
    const relation = R.head(stixRelations.edges).node;
    const target = await elLoadByIds(relation.toId);
    expect(target.name).toEqual(expect.stringContaining('malicious'));
    // Test with exact match
    filters = [{ key: 'connections', nested: [{ key: 'name', values: ['malicious'] }] }];
    options = { noCache, fromId: malware.internal_id, filters };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(0);
  });
  it.each(noCacheCases)('should list sightings (noCache = %s)', async (noCache) => {
    const stixSightings = await listRelations('stix-sighting-relationship', { noCache });
    expect(stixSightings).not.toBeNull();
    expect(stixSightings.edges.length).toEqual(3);
  });
  it.each(noCacheCases)('should list sightings with id option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const relationship = await elLoadByIds('relationship--8d2200a8-f9ef-4345-95d1-ba3ed49606f9');
    const options = { noCache, fromId: relationship.internal_id };
    const thing = await internalLoadById(relationship.internal_id);
    const stixSightings = await listRelations('stix-sighting-relationship', options);
    for (let index = 0; index < stixSightings.edges.length; index += 1) {
      const stixSighting = stixSightings.edges[index].node;
      expect(stixSighting.fromId).toEqual(thing.grakn_id);
    }
  });
});

describe('Element loader', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should load entity by id - internal (noCache = %s)', async (noCache) => {
    // No type
    const report = await elLoadByIds('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const internalId = report.internal_id;
    let element = await internalLoadById(internalId, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    expect(element.name).toEqual('A demo report for testing purposes');
    // Correct type
    element = await loadById(internalId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    // Wrong type
    element = await loadById(internalId, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { noCache });
    expect(element).toBeUndefined();
  });
  it.each(noCacheCases)('should load entity by id (noCache = %s)', async (noCache) => {
    // No type
    const report = await elLoadByIds('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const internalId = report.internal_id;
    const loadPromise = loadById(internalId, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadById(internalId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    expect(element.name).toEqual('A demo report for testing purposes');
  });
  it.each(noCacheCases)('should load entity by stix id (noCache = %s)', async (noCache) => {
    // No type
    const stixId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    const loadPromise = loadById(stixId, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.standard_id).toEqual('report--f3e554eb-60f5-587c-9191-4f25e9ba9f32');
    expect(element.name).toEqual('A demo report for testing purposes');
  });
  it.each(noCacheCases)('should load relation by id (noCache = %s)', async (noCache) => {
    // No type
    const relation = await elLoadByIds('relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02');
    const relationId = relation.internal_id;
    const loadPromise = loadById(relationId, null, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadById(relationId, 'uses', { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(relationId);
    expect(element.confidence).toEqual(3);
  });
  it.each(noCacheCases)('should load relation by stix id (noCache = %s)', async (noCache) => {
    const stixId = 'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02';
    const loadPromise = loadById(stixId, null, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadById(stixId, 'uses', { noCache });
    expect(element).not.toBeNull();
    expect(element.x_opencti_stix_ids).toEqual([stixId]);
    expect(element.confidence).toEqual(3);
  });
  it.each(noCacheCases)('should load by grakn id for multiple attributes (noCache = %s)', async (noCache) => {
    const stixId = 'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132';
    const identity = await loadById(stixId, ENTITY_TYPE_IDENTITY_ORGANIZATION, { noCache });
    expect(identity).not.toBeNull();
    expect(identity.x_opencti_aliases).not.toBeNull();
    expect(identity.x_opencti_aliases.length).toEqual(2);
    expect(identity.x_opencti_aliases.includes('Computer Incident')).toBeTruthy();
    expect(identity.x_opencti_aliases.includes('Incident')).toBeTruthy();
  });
});

describe('Attribute updated and indexed correctly', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should entity report attribute updated (noCache = %s)', async (noCache) => {
    const entityTypes = await findAllAttributes({ type: 'report_types' });
    expect(entityTypes).not.toBeNull();
    expect(entityTypes.edges.length).toEqual(2);
    const typeMap = new Map(entityTypes.edges.map((i) => [i.node.value, i]));
    const threatReportAttribute = typeMap.get('threat-report');
    expect(threatReportAttribute).not.toBeUndefined();
    const attributeId = threatReportAttribute.node.id;
    // 01. Get the report directly and test if type is "Threat report".
    const stixId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    let report = await loadById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_types).toEqual(['threat-report']);
    // 02. Update attribute "Threat report" to "Threat test"
    let updatedAttribute = await attributeEditField(SYSTEM_USER, attributeId, {
      key: 'value',
      value: ['threat-test'],
    });
    expect(updatedAttribute).not.toBeNull();
    // Wait a bit for elastic refresh
    await sleep(2000);
    // 03. Get the report directly and test if type is Threat test
    report = await loadById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_types).toEqual(['threat-test']);
    // 04. Back to original configuration
    updatedAttribute = await attributeEditField(SYSTEM_USER, attributeId, {
      key: 'value',
      value: ['threat-report'],
    });
    expect(updatedAttribute).not.toBeNull();
    // Wait a bit for elastic refresh
    await sleep(2000);
    report = await loadById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_types).toEqual(['threat-report']);
  });
});

describe('Entities time series', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should published entity time series (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, interval, inferred = false } = options;
    const options = {
      field: 'published',
      operation: 'count',
      interval: 'month',
      startDate: '2019-09-23T00:00:00.000+01:00',
      endDate: '2020-04-04T00:00:00.000+01:00',
      noCache,
    };
    const series = await timeSeriesEntities('Stix-Domain-Object', [], options);
    expect(series.length).toEqual(8);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020-02-29T23:00:00.000Z')).toEqual(1);
  });
  it.each(noCacheCases)('should start time relation time series (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, interval, inferred = false } = options;
    const intrusionSet = await elLoadByIds('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const filters = [{ isRelation: true, type: 'attributed-to', value: intrusionSet.internal_id }];
    const options = {
      field: 'first_seen',
      operation: 'count',
      interval: 'month',
      startDate: '2020-01-01T00:00:00+01:00',
      endDate: '2021-01-01T00:00:00+01:00',
      noCache,
    };
    const series = await timeSeriesEntities('Campaign', filters, options);
    expect(series.length).toEqual(13);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020-01-31T23:00:00.000Z')).toEqual(1);
  });
  it.each(noCacheCases)('should local filter time series (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, interval, inferred = false } = options;
    const filters = [{ type: 'name', value: 'A new campaign' }];
    const options = {
      field: 'first_seen',
      operation: 'count',
      interval: 'month',
      startDate: '2020-01-01T00:00:00+01:00',
      endDate: '2020-10-01T00:00:00+02:00',
      noCache,
    };
    const series = await timeSeriesEntities('Stix-Domain-Object', filters, options);
    expect(series.length).toEqual(10);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020-01-31T23:00:00.000Z')).toEqual(1);
  });
});

describe('Relations time series', () => {
  // const { startDate, endDate, operation, relationship_type, field, interval, fromId, inferred = false } = options;
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should relations first seen time series (noCache = %s)', async (noCache) => {
    // relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02 > 2020-02-29T23:00:00.000Z
    // relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de > 2020-02-29T23:00:00.000Z
    // relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3 > 2020-02-28T23:00:00.000Z
    const options = {
      relationship_type: 'uses',
      field: 'start_time',
      operation: 'count',
      interval: 'month',
      startDate: '2019-09-23T00:00:00.000+01:00',
      endDate: '2020-04-04T00:00:00.000+01:00',
      noCache,
    };
    const series = await timeSeriesRelations(options);
    expect(series.length).toEqual(8);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020-01-31T23:00:00.000Z')).toEqual(3);
  });
  it.each(noCacheCases)('should relations with fromId time series (noCache = %s)', async (noCache) => {
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = {
      fromId: malware.internal_id,
      relationship_type: 'uses',
      field: 'start_time',
      operation: 'count',
      interval: 'year',
      startDate: '2018-09-23T00:00:00.000+01:00',
      endDate: '2020-06-04T00:00:00.000+01:00',
      noCache,
    };
    const series = await timeSeriesRelations(options);
    expect(series.length).toEqual(3);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019-12-31T23:00:00.000Z')).toEqual(3);
  });
});

describe('Entities distribution', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should entity distribution (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, inferred, noCache } = options;
    const options = { field: 'entity_type', operation: 'count', limit: 20, noCache };
    const distribution = await distributionEntities('Stix-Domain-Object', [], options);
    expect(distribution.length).toEqual(17);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Malware')).toEqual(2);
    expect(aggregationMap.get('Campaign')).toEqual(1);
  });
  it.skip('should entity distribution filters (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, inferred, noCache } = options;
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { field: 'entity_type', operation: 'count', limit: 20, noCache };
    const start = '2020-02-28T22:59:00.000Z';
    const end = '2020-02-28T23:01:00.000Z';
    const relationFilter = {
      isRelation: true,
      type: 'uses',
      from: 'uses_from',
      to: 'uses_to',
      value: malware.internal_id,
      start,
      end,
    };
    const filters = [relationFilter];
    const distribution = await distributionEntities('Stix-Domain-Object', filters, options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
  });
  it.each(noCacheCases)('should entity distribution with date filtering (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, inferred, noCache } = options;
    const options = {
      field: 'entity_type',
      operation: 'count',
      limit: 20,
      startDate: '2018-03-01T00:00:00+01:00',
      endDate: '2018-03-02T00:00:00+01:00',
      noCache,
    };
    const distribution = await distributionEntities('Stix-Domain-Object', [], options);
    expect(distribution.length).toEqual(0);
  });
});

describe('Relations distribution', () => {
  // Malware Paradise Ransomware
  // --> attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc
  // ----------- relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02 > first_seen: 2020-02-29T23:00:00.000Z,
  // --> attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17
  // ----------- relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de > first_seen: 2020-02-29T23:00:00.000Z
  // <-- intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7
  // ----------- relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3 > first_seen: 2020-02-28T23:00:00.000Z
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should relation distribution (noCache = %s)', async (noCache) => {
    // const { limit = 50, order, noCache = false, inferred = false } = options;
    // const { startDate, endDate, relationship_type, toTypes, fromId, field, operation } = options;
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = {
      fromId: malware.internal_id,
      relationship_type: 'uses',
      field: 'entity_type',
      operation: 'count',
      noCache,
    };
    const distribution = await distributionRelations(options);
    expect(distribution.length).toEqual(2);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Attack-Pattern')).toEqual(2);
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
  });
  it.each(noCacheCases)('should relation distribution dates filtered (noCache = %s)', async (noCache) => {
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = {
      fromId: malware.internal_id,
      field: 'entity_type',
      operation: 'count',
      startDate: '2020-02-28T22:59:00.000Z',
      endDate: '2020-02-28T23:01:00.000Z',
      noCache,
    };
    const distribution = await distributionRelations(options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
  });
  it.each(noCacheCases)('should relation distribution filtered by to (noCache = %s)', async (noCache) => {
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = {
      fromId: malware.internal_id,
      field: 'entity_type',
      operation: 'count',
      toTypes: ['Attack-Pattern'],
      noCache,
    };
    const distribution = await distributionRelations(options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Attack-Pattern')).toEqual(2);
  });
});

// Some utils
const createThreat = async (input) => {
  const threat = await createEntity(ADMIN_USER, input, ENTITY_TYPE_THREAT_ACTOR);
  return loadByIdFullyResolved(threat.id, ENTITY_TYPE_THREAT_ACTOR);
};
const createFile = async (input) => {
  const file = await createEntity(ADMIN_USER, input, ENTITY_HASHED_OBSERVABLE_STIX_FILE);
  return loadByIdFullyResolved(file.id, ENTITY_HASHED_OBSERVABLE_STIX_FILE);
};
const isOneOfThisIdsExists = async (ids) => {
  const idsShould = ids.map((id) => ({ match_phrase: { 'internal_id.keyword': id } }));
  const connectionsShould = ids.map((id) => ({ match_phrase: { 'connections.internal_id.keyword': id } }));
  const relsShould = ids.map((id) => ({ multi_match: { query: id, type: 'phrase', fields: ['rel_*'] } }));
  const nestedConnections = {
    nested: {
      path: 'connections',
      query: {
        bool: {
          should: connectionsShould,
          minimum_should_match: 1,
        },
      },
    },
  };
  const query = {
    index: DATA_INDICES,
    size: 5000,
    body: {
      query: {
        bool: {
          should: [...idsShould, ...relsShould, nestedConnections],
          minimum_should_match: 1,
        },
      },
    },
  };
  const looking = await el.search(query);
  const numberOfResult = looking.body.hits.total.value;
  return numberOfResult > 0;
};

describe('Upsert and merge entities', () => {
  const testMarking = 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27';
  const whiteMarking = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';
  const mitreMarking = 'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168';
  it('should entity upserted', async () => {
    const markingId = 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27';
    // Most simple entity
    const malware = { name: 'MALWARE_TEST', description: 'MALWARE_TEST DESCRIPTION' };
    const createdMalware = await createEntity(ADMIN_USER, malware, ENTITY_TYPE_MALWARE);
    expect(createdMalware).not.toBeNull();
    expect(createdMalware.name).toEqual('MALWARE_TEST');
    expect(createdMalware.description).toEqual('MALWARE_TEST DESCRIPTION');
    expect(createdMalware.i_aliases_ids.length).toEqual(1); // We put the name as internal alias id
    let loadMalware = await loadByIdFullyResolved(createdMalware.id, ENTITY_TYPE_MALWARE);
    expect(loadMalware).not.toBeNull();
    expect(loadMalware.objectMarking).toEqual(undefined);
    // Upsert TLP by name
    let upMalware = { name: 'MALWARE_TEST', objectMarking: [markingId] };
    let upsertedMalware = await createEntity(ADMIN_USER, upMalware, ENTITY_TYPE_MALWARE);
    expect(upsertedMalware).not.toBeNull();
    expect(upsertedMalware.id).toEqual(createdMalware.id);
    expect(upsertedMalware.name).toEqual('MALWARE_TEST');
    loadMalware = await loadByIdFullyResolved(createdMalware.id, ENTITY_TYPE_MALWARE);
    expect(loadMalware.objectMarking.length).toEqual(1);
    expect(R.head(loadMalware.objectMarking).standard_id).toEqual(
      'marking-definition--907bb632-e3c2-52fa-b484-cf166a7d377c'
    );
    // Upsert definition per alias
    upMalware = {
      name: 'NEW NAME',
      description: 'MALWARE_TEST NEW',
      stix_id: 'malware--907bb632-e3c2-52fa-b484-cf166a7d377e',
      update: true,
      aliases: ['MALWARE_TEST'],
    };
    upsertedMalware = await createEntity(ADMIN_USER, upMalware, ENTITY_TYPE_MALWARE);
    expect(upsertedMalware.name).toEqual('MALWARE_TEST');
    expect(upsertedMalware.description).toEqual('MALWARE_TEST NEW');
    expect(upsertedMalware.id).toEqual(createdMalware.id);
    expect(upsertedMalware.x_opencti_stix_ids).toEqual(['malware--907bb632-e3c2-52fa-b484-cf166a7d377e']);
    expect(upsertedMalware.aliases.sort()).toEqual(['NEW NAME', 'MALWARE_TEST'].sort());
    loadMalware = await loadByIdFullyResolved(createdMalware.id, ENTITY_TYPE_MALWARE);
    expect(loadMalware.name).toEqual('MALWARE_TEST');
    expect(loadMalware.description).toEqual('MALWARE_TEST NEW');
    expect(loadMalware.id).toEqual(loadMalware.id);
    expect(loadMalware.x_opencti_stix_ids).toEqual(['malware--907bb632-e3c2-52fa-b484-cf166a7d377e']);
    expect(loadMalware.aliases.sort()).toEqual(['NEW NAME', 'MALWARE_TEST'].sort());
    // Delete the malware
    await deleteElementById(ADMIN_USER, createdMalware.id, ENTITY_TYPE_MALWARE);
  });
  it('should entity merged', async () => {
    // 01. Create malware
    const malware01 = await createEntity(ADMIN_USER, { name: 'MALWARE_TEST_01' }, ENTITY_TYPE_MALWARE);
    const malware02 = await createEntity(ADMIN_USER, { name: 'MALWARE_TEST_02' }, ENTITY_TYPE_MALWARE);
    const malware03 = await createEntity(ADMIN_USER, { name: 'MALWARE_TEST_03' }, ENTITY_TYPE_MALWARE);
    // 02. Create threat actors
    // target
    const targetInput01 = {
      name: 'THREAT_MERGE',
      description: 'DESC',
      objectMarking: [testMarking],
      objectLabel: ['identity', 'malware'],
    };
    let target = await createThreat(targetInput01);
    await createRelation(ADMIN_USER, {
      fromId: target.internal_id,
      toId: malware01.internal_id,
      relationship_type: RELATION_USES,
    });
    target = await loadByIdFullyResolved(target.id, ENTITY_TYPE_THREAT_ACTOR);
    // source 01
    const sourceInput01 = {
      name: 'THREAT_SOURCE_01',
      goals: ['MY GOAL'],
      objectMarking: [whiteMarking, mitreMarking],
      objectLabel: ['report', 'opinion', 'malware'],
    };
    const source01 = await createThreat(sourceInput01);
    // source 02
    const sourceInput02 = {
      name: 'THREAT_SOURCE_02',
      objectMarking: [testMarking, whiteMarking, mitreMarking],
      objectLabel: ['report', 'note', 'malware'],
    };
    let source02 = await createThreat(sourceInput02);
    await createRelation(ADMIN_USER, {
      fromId: source02.internal_id,
      toId: malware02.internal_id,
      relationship_type: RELATION_USES,
      objectMarking: [testMarking, whiteMarking, mitreMarking],
      objectLabel: ['report', 'note', 'malware'],
    });
    source02 = await loadByIdFullyResolved(source02.id, ENTITY_TYPE_THREAT_ACTOR);
    // source 03
    const sourceInput03 = { name: 'THREAT_SOURCE_03', objectMarking: [testMarking], objectLabel: ['note', 'malware'] };
    let source03 = await createThreat(sourceInput03);
    const duplicateRel = await createRelation(ADMIN_USER, {
      fromId: source03.internal_id,
      toId: malware02.internal_id,
      relationship_type: RELATION_USES,
      objectMarking: [testMarking, whiteMarking, mitreMarking],
      objectLabel: ['report', 'note', 'malware'],
    });
    source03 = await loadByIdFullyResolved(source03.id, ENTITY_TYPE_THREAT_ACTOR);
    // source 04
    const sourceInput04 = {
      name: 'THREAT_SOURCE_04',
      objectMarking: [whiteMarking],
      objectLabel: ['report', 'opinion', 'note', 'malware', 'identity'],
    };
    const source04 = await createThreat(sourceInput04);
    // source 05
    const sourceInput05 = { name: 'THREAT_SOURCE_05' };
    const source05 = await createThreat(sourceInput05);
    // source 06
    const sourceInput06 = { name: 'THREAT_SOURCE_06', objectMarking: [testMarking, whiteMarking, mitreMarking] };
    let source06 = await createThreat(sourceInput06);
    await createRelation(ADMIN_USER, {
      fromId: source06.internal_id,
      toId: malware03.internal_id,
      relationship_type: RELATION_USES,
    });
    source06 = await loadByIdFullyResolved(source06.id, ENTITY_TYPE_THREAT_ACTOR);
    // Merge with fully resolved entities
    const merged = await mergeEntities(ADMIN_USER, target, [
      source01,
      source02,
      source03,
      source04,
      source05,
      source06,
    ]);
    const loadedThreat = await loadByIdFullyResolved(merged.id, ENTITY_TYPE_THREAT_ACTOR);
    // List of ids that should disappears
    const idsThatShouldNotExists = [
      source01.internal_id,
      source02.internal_id,
      source03.internal_id,
      source04.internal_id,
      source05.internal_id,
      source06.internal_id,
      duplicateRel.internal_id,
    ];
    const isExist = await isOneOfThisIdsExists(idsThatShouldNotExists);
    expect(isExist).toBeFalsy();
    // Test the merged data
    expect(loadedThreat).not.toBeNull();
    expect(loadedThreat.aliases.length).toEqual(6); // [THREAT_SOURCE_01, THREAT_SOURCE_02, THREAT_SOURCE_03, THREAT_SOURCE_04, THREAT_SOURCE_05, THREAT_SOURCE_06]
    expect(loadedThreat.i_aliases_ids.length).toEqual(7);
    expect(loadedThreat.goals).toEqual(['MY GOAL']);
    expect(loadedThreat.objectMarking.length).toEqual(3); // [testMarking, whiteMarking, mitreMarking]
    expect(loadedThreat.objectLabel.length).toEqual(5); // ['report', 'opinion', 'note', 'malware', 'identity']
    expect(loadedThreat.uses.length).toEqual(3); // [MALWARE_TEST_01, MALWARE_TEST_02, MALWARE_TEST_03]
    // Cleanup
    await deleteElementById(ADMIN_USER, malware01.id, ENTITY_TYPE_MALWARE);
    await deleteElementById(ADMIN_USER, malware02.id, ENTITY_TYPE_MALWARE);
    await deleteElementById(ADMIN_USER, malware03.id, ENTITY_TYPE_MALWARE);
    await deleteElementById(ADMIN_USER, loadedThreat.id, ENTITY_TYPE_MALWARE);
  });
  it('should observable merged by update', async () => {
    // Merged 3 Stix File into one
    const md5 = await createFile({ hashes: { MD5: 'MERGE_MD5' }, objectMarking: [whiteMarking] });
    const sha1 = await createFile({
      hashes: { 'SHA-1': 'MERGE_SHA-1' },
      objectMarking: [testMarking, whiteMarking, mitreMarking],
    });
    const sha256 = await createFile({
      hashes: { 'SHA-256': 'MERGE_SHA-256' },
      objectMarking: [testMarking, whiteMarking, mitreMarking],
    });
    // merge by update
    const md5Input = { key: 'hashes.MD5', value: ['MERGE_MD5'] };
    const patchSha1 = updateAttribute(SYSTEM_USER, sha1.internal_id, ENTITY_HASHED_OBSERVABLE_STIX_FILE, [md5Input]);
    // eslint-disable-next-line prettier/prettier
    const patchSha256 = updateAttribute(SYSTEM_USER, sha256.internal_id, ENTITY_HASHED_OBSERVABLE_STIX_FILE, [md5Input]);
    await Promise.all([patchSha1, patchSha256]);
    // Check
    const idsThatShouldNotExists = [sha1.internal_id, sha256.internal_id];
    const isExist = await isOneOfThisIdsExists(idsThatShouldNotExists);
    expect(isExist).toBeFalsy();
    const reloadMd5 = await loadByIdFullyResolved(md5.id, ENTITY_HASHED_OBSERVABLE_STIX_FILE);
    expect(reloadMd5).not.toBeNull();
    expect(reloadMd5.hashes).not.toBeNull();
    expect(reloadMd5.hashes.MD5).toEqual('MERGE_MD5');
    expect(reloadMd5.hashes['SHA-1']).toEqual('MERGE_SHA-1');
    expect(reloadMd5.hashes['SHA-256']).toEqual('MERGE_SHA-256');
    expect(reloadMd5.objectMarking.length).toEqual(3); // [testMarking, whiteMarking, mitreMarking]
    // Cleanup
    await deleteElementById(ADMIN_USER, reloadMd5.id, ENTITY_HASHED_OBSERVABLE_STIX_FILE);
  });
});

describe('Elements deletions', () => {
  it('should all elements correctly deleted (noCache = %s)', async () => {
    // Create entities
    const label = await addLabel(ADMIN_USER, { value: 'MY LABEL' });
    const intrusionSet = await createEntity(
      ADMIN_USER,
      { name: 'MY ISET', description: 'MY ISET' },
      ENTITY_TYPE_INTRUSION_SET
    );
    const malware = await createEntity(ADMIN_USER, { name: 'MY MAL', description: 'MY MAL' }, ENTITY_TYPE_MALWARE);
    const indicator = await createEntity(
      ADMIN_USER,
      { name: 'MY INDIC', pattern: 'pattern', pattern_type: 'pattern-type' },
      ENTITY_TYPE_INDICATOR
    );
    // Create basic relations
    // eslint-disable-next-line camelcase
    const intrusionSet_uses_Malware = await createRelation(ADMIN_USER, {
      fromId: intrusionSet.internal_id,
      toId: malware.internal_id,
      relationship_type: 'uses',
    });
    // eslint-disable-next-line camelcase
    const indicator_indicated_uses = await createRelation(ADMIN_USER, {
      fromId: indicator.internal_id,
      toId: intrusionSet_uses_Malware.internal_id,
      relationship_type: 'indicates',
    });
    // Create labels relations
    const intrusionSetLabel = await createRelation(ADMIN_USER, {
      fromId: intrusionSet.internal_id,
      toId: label.internal_id,
      relationship_type: 'object-label',
    });
    const relIndicatesLabel = await createRelation(ADMIN_USER, {
      fromId: indicator_indicated_uses.internal_id,
      toId: label.internal_id,
      relationship_type: 'object-label',
    });
    const malwareLabel = await createRelation(ADMIN_USER, {
      fromId: malware.internal_id,
      toId: label.internal_id,
      relationship_type: 'object-label',
    });
    // Delete the intrusion set, check all relation what need to be deleted
    const toBeDeleted = [
      intrusionSet.internal_id,
      intrusionSet_uses_Malware.internal_id,
      indicator_indicated_uses.internal_id,
      intrusionSetLabel.internal_id,
      relIndicatesLabel.internal_id,
    ];
    await deleteElementById(ADMIN_USER, intrusionSet.internal_id, ENTITY_TYPE_INTRUSION_SET);
    const isExist = await isOneOfThisIdsExists(toBeDeleted);
    expect(isExist).toBeFalsy();
    const resolvedMalware = await loadById(malware.internal_id, ENTITY_TYPE_MALWARE);
    expect(resolvedMalware).not.toBeUndefined();
    const resolvedRelationLabel = await loadById(malwareLabel.internal_id, RELATION_OBJECT_LABEL);
    expect(resolvedRelationLabel).not.toBeUndefined();
  });
});
