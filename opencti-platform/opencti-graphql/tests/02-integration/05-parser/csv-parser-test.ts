import { describe, expect, it } from 'vitest';
import { csvMapperMockSimpleEntity } from './simple-entity-test/csv-mapper-mock-simple-entity';
import { isNotEmptyField } from '../../../src/database/utils';
import { csvMapperMockSimpleRelationship } from './simple-relationship-test/csv-mapper-mock-simple-relationship';
import { csvMapperMockSimpleEntityWithRef } from './simple-entity-with-ref-test/csv-mapper-mock-simple-entity-with-ref';
import { csvMapperMockRealUseCase } from './real-use-case/csv-mapper-mock-real-use-case';
import { csvMapperMockSimpleDifferentEntities } from './dynamic-simple-test/csv-mapper-mock-simple-different-entities';
import { csvMapperMockSimpleDifferentEntities } from '../../data/csv-mapper-mock-simple-different-entities';
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
import type { StixDomainName, StixEmailAddress, StixFile, StixIPv4Address, StixIPv6Address, StixURL } from '../../../src/types/stix-sco';
import { csvMapperMockFileHashHack } from './dynamic-file-hash/csv-mapper-mock-file-hash-hack';
import { STIX_EXT_OCTI_SCO } from '../../../src/types/stix-extensions';
import { csvMapperDynamicChar } from './dynamic-url-ip-character/csv-mapper-mock-url-ip-char';

describe('CSV-PARSER', () => {
  it('Parse CSV - Simple entity', async () => {
    const filPath = './tests/02-integration/05-parser/simple-entity-test/Threat-Actor-Group_list.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filPath, csvMapperMockSimpleEntity as CsvMapperParsed);
    const threatActors = objects as StixThreatActor[];
    expect(threatActors.length).toBe(5);
    expect(threatActors.filter((o: StixThreatActor) => isNotEmptyField(o.name)).length).toBe(5);
    const threatActorWithTypes = threatActors.filter((o: StixThreatActor) => isNotEmptyField(o.threat_actor_types))[0];
    expect(threatActorWithTypes).not.toBeNull();
    expect(threatActorWithTypes.threat_actor_types.length).toBe(2);
  });

  it('Parse CSV - Simple relationship', async () => {
    const filPath = './tests/02-integration/05-parser/simple-relationship-test/Threat-Actor-Group_PART-OF_list.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filPath, csvMapperMockSimpleRelationship as CsvMapperParsed);
    expect(objects.length).toBe(6);
    const threatActors: StixThreatActor[] = objects.filter((o) => o.type === 'threat-actor') as StixThreatActor[];
    expect(threatActors.length).toBe(4);
    const relationships: StixRelation[] = objects.filter((o) => o.type === 'relationship') as StixRelation[];
    expect(relationships.filter((o) => o.relationship_type === 'part-of').length).toBe(2);
  });

  it('Parse CSV - Simple sighting', async () => {
    const filPath = './tests/02-integration/05-parser/simple-sighting-test/Threat-Actor-Group_SIGHTING_org.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filPath, csvMapperMockSimpleSighting as CsvMapperParsed);

    expect(objects.length).toBe(3);
    expect(objects.filter((o) => o.type === 'threat-actor').length).toBe(1);
    expect(objects.filter((o) => o.type === 'identity').length).toBe(1);
    expect(objects.filter((o) => o.type === 'sighting').length).toBe(1);

    const sightings: StixSighting[] = objects.filter((o) => o.type === 'sighting') as StixSighting[];
    expect(sightings[0].first_seen).not.toBeUndefined();
    expect(sightings[0].last_seen).toBeUndefined();
  });

  it('Parse CSV - Simple entity with refs', async () => {
    const filPath = './tests/02-integration/05-parser/simple-entity-with-ref-test/Threat-Actor-Group_with-ref.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filPath, csvMapperMockSimpleEntityWithRef as CsvMapperParsed);

    expect(objects.length)
      .toBe(3);
    const label = objects.filter((o) => o.type === 'label')[0];
    const createdBy = objects.filter((o) => o.type === 'identity')[0];
    const threatActor = objects.filter((o) => o.type === 'threat-actor')[0] as StixThreatActor;
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

  it('Parse CSV - Simple different entities', async () => {
    const filPath = './tests/02-integration/05-parser/simple-different-entities-test/Threat-Actor-Group_or_Organization.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filPath, csvMapperMockSimpleDifferentEntities as CsvMapperParsed);

    expect(objects.length)
      .toBe(2);
    expect(objects.filter((o) => o.type === 'threat-actor').length)
      .toBe(1);
    expect(objects.filter((o) => o.type === 'identity').length)
      .toBe(1);
  });

  it('Parse CSV - Real use case', async () => {
    const filPath = './tests/02-integration/05-parser/real-use-case/schema incidents.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filPath, csvMapperMockRealUseCase as CsvMapperParsed);

    const incidents = objects.filter((o) => o.type === 'incident');
    expect(incidents.length).toBe(118);

    const countries : StixLocation[] = objects.filter((o) => o.type === 'location') as StixLocation[];
    const uniqueCountries: string[] = [...new Set(countries.map((location) => location.name))];
    expect(uniqueCountries.length).toBe(35);
      .toBe(118);
    const identities: StixIdentity[] = objects.filter((o) => o.type === 'identity') as StixIdentity[]; // Sectors & organizations
    const uniqueIdentities: string[] = [...new Set(identities.map((identity) => identity.name))];
      .toBe(130);

    const threatActors = objects.filter((o) => o.type === 'threat-actor') as StixThreatActor[];
      .toBe(160);
    expect(uniqueThreatActors.length).toBe(42);

    const relationships: StixRelation[] = objects.filter((o) => o.type === 'relationship') as StixRelation[];
    const relationshipTargets = relationships.filter((o) => o.relationship_type === 'targets');
    expect(relationshipTargets.length).toBe(118);
    const relationshipLocatedAt = relationships.filter((o) => o.relationship_type === 'located-at');
    expect(relationshipLocatedAt.length).toBe(130);
    const relationshipPartOf = relationships.filter((o) => o.relationship_type === 'part-of');
    expect(relationshipPartOf.length).toBe(160);
  });

  it('Parse CSV - Simple skip line test on Simple entity ', async () => {
    const filPath = './tests/02-integration/05-parser/simple-skip-line-test/Threat-Actor-Group_list_skip_line.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filPath, csvMapperMockSimpleSkipLine as CsvMapperParsed);
    const threatActors: StixThreatActor[] = objects as StixThreatActor[];

    expect(threatActors.length).toBe(5);
    expect(threatActors.filter((o) => isNotEmptyField(o.name)).length).toBe(5);
    const threatActorWithTypes = threatActors.filter((o) => isNotEmptyField(o.threat_actor_types))[0];
    expect(threatActorWithTypes).not.toBeNull();
    expect(threatActorWithTypes.threat_actor_types.length).toBe(2);
  });

  it('Parse CSV - Simple skip double quoted data line test on Simple entity ', async () => {
    const filePath = './tests/02-integration/05-parser/simple-skip-line-test/Threat-Actor-Group_list_skip_double_quoted_data_line.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filePath, csvMapperMockSimpleSkipLine as CsvMapperParsed);
    const threatActors: StixThreatActor[] = objects as StixThreatActor[];
    expect(threatActors.length).toBe(3);
    expect(threatActors.filter((o) => isNotEmptyField(o.name)).length).toBe(3);
  });

  it('Parse CSV - manage boolean values', async () => {
    const filePath = './tests/02-integration/05-parser/entities-with-booleans/malwares.csv';
    const objects = await bundleProcessFromFile(testContext, ADMIN_USER, filePath, csvMapperMalware as CsvMapperParsed);

    expect(objects.length).toBe(4);
    const malwares = objects as StixMalware[];
    expect(malwares[0].is_family).toBe(true);
    expect(malwares[1].is_family).toBe(false);
    expect(malwares[2].is_family).toBe(true);
    expect(malwares[3].is_family).toBe(true);
  });
});
