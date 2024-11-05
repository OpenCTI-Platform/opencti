import { describe, expect, it } from 'vitest';
import { csvMapperMockSimpleEntity } from './simple-entity-test/csv-mapper-mock-simple-entity';
import { isNotEmptyField } from '../../../src/database/utils';
import { csvMapperMockSimpleRelationship } from './simple-relationship-test/csv-mapper-mock-simple-relationship';
import { csvMapperMockSimpleEntityWithRef } from './simple-entity-with-ref-test/csv-mapper-mock-simple-entity-with-ref';
import { csvMapperMockRealUseCase } from './real-use-case/csv-mapper-mock-real-use-case';
import { csvMapperMockSimpleDifferentEntities } from './dynamic-simple-test/csv-mapper-mock-simple-different-entities';
import { csvMapperMockSimpleSighting } from './simple-sighting-test/csv-mapper-mock-simple-sighting';
import { bundleProcess } from '../../../src/parser/csv-bundler';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { csvMapperMockSimpleSkipLine } from './simple-skip-line-test/csv-mapper-mock-simple-skip-line';
import { csvMapperMalware } from './entities-with-booleans/mapper';

import '../../../src/modules';
import type { StixBundle } from '../../../src/types/stix-common';
import type { CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import type { StixIdentity, StixMalware, StixThreatActor } from '../../../src/types/stix-sdo';
import type { StixRelation, StixSighting } from '../../../src/types/stix-sro';
import { csvMapperDynamicIpAndUrl } from './dynamic-url-and-ip/mapper-url-ip';
import type { StixFile, StixIPv4Address, StixURL } from '../../../src/types/stix-sco';
import { csvMapperMockFileHashHack } from './dynamic-file-hash/csv-mapper-mock-file-hash-hack';
import { STIX_EXT_OCTI_SCO } from '../../../src/types/stix-extensions';

describe('CSV-PARSER', () => {
  it('Parse CSV - Simple entity', async () => {
    const filPath = './tests/02-integration/05-parser/simple-entity-test/Threat-Actor-Group_list.csv';
    const bundle: StixBundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMockSimpleEntity as CsvMapperParsed);

    const { objects } = bundle;
    expect(objects.length).toBe(5);
    const threatActors: StixThreatActor[] = objects.filter((o) => o.type === 'threat-actor') as StixThreatActor[];
    expect(threatActors.filter((o) => isNotEmptyField(o.name)).length).toBe(5);
    const threatActorWithTypes = threatActors.filter((o) => isNotEmptyField(o.threat_actor_types))[0];
    expect(threatActorWithTypes)
      .not
      .toBeNull();
    expect(threatActorWithTypes.threat_actor_types.length)
      .toBe(2);
  });

  it('Parse CSV - Simple relationship', async () => {
    const filPath = './tests/02-integration/05-parser/simple-relationship-test/Threat-Actor-Group_PART-OF_list.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMockSimpleRelationship as CsvMapperParsed);

    const { objects } = bundle;
    expect(objects.length).toBe(6);
    expect(objects.filter((o) => o.type === 'threat-actor').length).toBe(4);

    const relations: StixRelation[] = objects as StixRelation[];
    expect(relations.filter((o) => o.relationship_type === 'part-of').length).toBe(2);
  });

  it('Parse CSV - Simple sighting', async () => {
    const filPath = './tests/02-integration/05-parser/simple-sighting-test/Threat-Actor-Group_SIGHTING_org.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMockSimpleSighting as CsvMapperParsed);

    const { objects } = bundle;
    expect(objects.length)
      .toBe(3);
    expect(objects.filter((o) => o.type === 'threat-actor').length)
      .toBe(1);
    expect(objects.filter((o) => o.type === 'identity').length)
      .toBe(1);
    expect(objects.filter((o) => o.type === 'sighting').length)
      .toBe(1);
    const sighting: StixSighting = objects.filter((o) => o.type === 'sighting')[0] as StixSighting;
    expect(sighting.first_seen).not.toBeUndefined();
    expect(sighting.last_seen).toBeUndefined();
  });

  it('Parse CSV - Simple entity with refs', async () => {
    const filPath = './tests/02-integration/05-parser/simple-entity-with-ref-test/Threat-Actor-Group_with-ref.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMockSimpleEntityWithRef as CsvMapperParsed);

    const { objects } = bundle;
    expect(objects.length)
      .toBe(3);
    const label = objects.filter((o) => o.type === 'label')[0];
    const createdBy = objects.filter((o) => o.type === 'identity')[0];
    const threatActor: StixThreatActor = objects.filter((o) => o.type === 'threat-actor')[0] as StixThreatActor;
    expect(label)
      .not
      .toBeNull();
    expect(createdBy)
      .not
      .toBeNull();
    expect(threatActor)
      .not
      .toBeNull();
    expect(threatActor.labels.length)
      .toBe(1);
    expect(threatActor.created_by_ref)
      .not
      .toBeNull();
  });

  it('Parse CSV - Real use case', async () => {
    const filPath = './tests/02-integration/05-parser/real-use-case/schema incidents.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMockRealUseCase as CsvMapperParsed);

    const { objects } = bundle;
    const incidents = objects.filter((o) => o.type === 'incident');
    expect(incidents.length)
      .toBe(118);
    const countries = objects.filter((o) => o.type === 'location'); // Countries
    expect(countries.length)
      .toBe(35);
    const identities = objects.filter((o) => o.type === 'identity'); // Sectors & organizations
    expect(identities.length)
      .toBe(131);
    const threatActors = objects.filter((o) => o.type === 'threat-actor');
    expect(threatActors.length)
      .toBe(42);

    const relations: StixRelation[] = objects as StixRelation[];
    const relationshipTargets = relations.filter((o) => o.relationship_type === 'targets');
    expect(relationshipTargets.length)
      .toBe(118);
    const relationshipLocatedAt = relations.filter((o) => o.relationship_type === 'located-at');
    expect(relationshipLocatedAt.length)
      .toBe(130);
    const relationshipPartOf = relations.filter((o) => o.relationship_type === 'part-of');
    expect(relationshipPartOf.length)
      .toBe(160);
  });

  it('Parse CSV - Simple skip line test on Simple entity ', async () => {
    const filPath = './tests/02-integration/05-parser/simple-skip-line-test/Threat-Actor-Group_list_skip_line.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMockSimpleSkipLine as CsvMapperParsed);
    const { objects } = bundle;
    const threatActors: StixThreatActor[] = objects as StixThreatActor[];
    expect(objects.length)
      .toBe(5);
    expect(threatActors.filter((o) => isNotEmptyField(o.name)).length)
      .toBe(5);
    const threatActorWithTypes = threatActors.filter((o) => isNotEmptyField(o.threat_actor_types))[0];
    expect(threatActorWithTypes)
      .not
      .toBeNull();
    expect(threatActorWithTypes.threat_actor_types.length)
      .toBe(2);
  });

  it('Parse CSV - Simple skip double quoted data line test on Simple entity ', async () => {
    const filPath = './tests/02-integration/05-parser/simple-skip-line-test/Threat-Actor-Group_list_skip_double_quoted_data_line.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMockSimpleSkipLine as CsvMapperParsed);
    const { objects } = bundle;
    const threatActors: StixThreatActor[] = objects as StixThreatActor[];
    expect(objects.length)
      .toBe(3);
    expect(threatActors.filter((o) => isNotEmptyField(o.name)).length)
      .toBe(3);
  });

  it('Parse CSV - manage boolean values', async () => {
    const filPath = './tests/02-integration/05-parser/entities-with-booleans/malwares.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMalware as CsvMapperParsed);
    const { objects } = bundle;
    const malwares: StixMalware[] = objects as StixMalware[];
    expect(objects.length).toBe(4);
    expect(malwares[0].is_family).toBe(true);
    expect(malwares[1].is_family).toBe(false);
    expect(malwares[2].is_family).toBe(true);
    expect(malwares[3].is_family).toBe(true);
  });
});

describe('CSV-PARSER with dynamic mapping (aka different entity on one file)', () => {
  it('Parse CSV - Simple different entities', async () => {
    const filPath = './tests/02-integration/05-parser/dynamic-simple-test/Threat-Actor-Group_or_Organization.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filPath, csvMapperMockSimpleDifferentEntities as CsvMapperParsed);

    const { objects } = bundle;
    expect(objects.length).toBe(2);
    expect(objects.filter((o) => o.type === 'threat-actor').length).toBe(1);
    expect(objects.filter((o) => o.type === 'identity').length).toBe(1);
  });

  it('Parse CSV - dynamic entity with IPs and URLs', async () => {
    const filePath = './tests/02-integration/05-parser/dynamic-url-and-ip/url-ip.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filePath, csvMapperDynamicIpAndUrl as CsvMapperParsed);

    const { objects } = bundle;
    expect(objects.length).toBe(77); // 76 lines + 1 individual
    const firstUrl: StixURL = objects.filter((o) => o.type === 'url')[0] as StixURL;
    const firstIp: StixIPv4Address = objects.filter((o) => o.type === 'ipv4-addr')[0] as StixIPv4Address;
    const firstIdentity: StixIdentity = objects.filter((o) => o.type === 'identity')[0] as StixIdentity;

    expect(firstIdentity.name).toBe('AlienVault');
    expect(firstIp.value).toBe('91.200.148.232');
    expect(firstIp.extensions[STIX_EXT_OCTI_SCO].score).toBe(41);
    expect(firstUrl.value).toBe('http://requestrepo.com/r/2yxp98b3');
    expect(firstUrl.extensions[STIX_EXT_OCTI_SCO].score).toBe(22);
    expect(firstIdentity.name).toBe('AlienVault');
    expect(firstIdentity.identity_class).toBe('individual');
  });

  it('Parse CSV - dynamic entity with MD5 and SHA-256 files', async () => {
    const filePath = './tests/02-integration/05-parser/dynamic-file-hash/distinct-hash.csv';
    const bundle = await bundleProcess(testContext, ADMIN_USER, filePath, csvMapperMockFileHashHack as CsvMapperParsed);

    const { objects } = bundle;
    expect(objects.length).toBe(7);

    const firstFile: StixFile = objects.filter((o) => o.type === 'file')[0] as StixFile;

    expect(firstFile.name).toBe('file1');
    expect(firstFile.id).toBe('file--0e482844-d44d-582b-9f40-6e05aec3b39f');
    expect(firstFile.type).toBe('file');
    expect(Object.values(firstFile.hashes)[0]).toBe('D9F73A41BE35198AB3867A4D0C642642B54FB81B528124523D6CF506435A2264');
  });
});
