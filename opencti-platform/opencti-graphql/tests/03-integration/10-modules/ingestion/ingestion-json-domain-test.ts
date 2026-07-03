import { Readable } from 'node:stream';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { addIngestionJson, deleteIngestionJson, ingestionJsonEditField, testJsonIngestionMapping } from '../../../../src/modules/ingestion/ingestion-json-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type EditInput, IngestionAuthType, type IngestionJsonAddInput, JsonMapperRepresentationType } from '../../../../src/generated/graphql';
import * as ingestionConfigMock from '../../../../src/manager/ingestionManager/ingestionManagerConfiguration';
import type { BasicStoreEntityIngestionJson } from '../../../../src/modules/ingestion/ingestion-types';
import { createJsonMapper, deleteJsonMapper, jsonMapperTest } from '../../../../src/modules/internal/jsonMapper/jsonMapper-domain';
import type { FileUploadData } from '../../../../src/database/file-storage';
import { regexpTestData, representationsFormulaMatrix, representationsRegExpr, stixBundleDataFormulaMatrix } from './ingestionManager-testData/ingestion-json-data';
import { ENTITY_TYPE_TOOL } from '../../../../src/schema/stixDomainObject';

describe('Ingestion Json domain - Deny list coverage', async () => {
  let myJsonFeed: BasicStoreEntityIngestionJson;

  afterAll(async () => {
    if (myJsonFeed && myJsonFeed.id) {
      await deleteIngestionJson(testContext, ADMIN_USER, myJsonFeed.id);
    }
  });

  it('should be able to create a JSON feed with an allowed URI, and refused field patch of denied URL', async () => {
    vi.spyOn(ingestionConfigMock, 'ingestionUriDenyList').mockReturnValue(['*.denied.com']);

    const creationInput: IngestionJsonAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'Test JSON feed deny list',
      uri: 'https://example.allowed.com/json-feed',
      user_id: ADMIN_USER.id,
      json_mapper_id: 'fake-mapper-id',
      verb: 'GET',
    };
    myJsonFeed = await addIngestionJson(testContext, ADMIN_USER, creationInput) as unknown as BasicStoreEntityIngestionJson;

    const fieldPatchInput: EditInput[] = [{
      key: 'uri',
      value: ['https://example.denied.com/json-feed'],
    }];
    await expect(ingestionJsonEditField(testContext, ADMIN_USER, myJsonFeed.id, fieldPatchInput))
      .rejects.toThrow('This URI is not allowed for ingestion.');
  });

  it('should test be denied when URL is in deny list', async () => {
    vi.spyOn(ingestionConfigMock, 'ingestionUriDenyList').mockReturnValue(['*.denied.com']);

    const testInput: IngestionJsonAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'Test JSON feed deny list',
      uri: 'https://example.denied.com/json-feed',
      user_id: ADMIN_USER.id,
      json_mapper_id: 'fake-mapper-id',
      verb: 'GET',
    };
    await expect(testJsonIngestionMapping(testContext, ADMIN_USER, testInput))
      .rejects.toThrow('This URI is not allowed for ingestion.');
  });
});

describe('Ingestion Json domain - complex path coverage', async () => {
  let mapperId: string;

  afterAll(async () => {
    if (mapperId) {
      await deleteJsonMapper(testContext, ADMIN_USER, mapperId);
    }
  });

  it('should be able to create a JSON mapper using formula', async () => {
    const input = {
      name: 'STIX Bundle Formula Mapper',
      representations: JSON.stringify(representationsFormulaMatrix),
    };

    const mapper = await createJsonMapper(testContext, ADMIN_USER, input);
    expect(mapper).toBeDefined();
    expect(mapper.id).toBeDefined();
    expect(mapper.name).toBe('STIX Bundle Formula Mapper');
    mapperId = mapper.id;
  });

  it('should parse STIX bundle data using jsonMapperTest with formulas', async () => {
    const configuration = JSON.stringify({
      name: 'STIX Bundle Formula Mapper',
      representations: representationsFormulaMatrix,
    });

    const fileUpload: Promise<FileUploadData> = Promise.resolve({
      createReadStream: () => Readable.from(Buffer.from(stixBundleDataFormulaMatrix)),
      filename: 'stix-bundle.json',
      mimeType: 'application/json',
    });

    const result = await jsonMapperTest(testContext, ADMIN_USER, configuration, fileUpload);

    expect(result).toBeDefined();
    expect(result.nbEntities).toBeGreaterThan(0);
    // 1 organization + 3 tools = 4 entities
    expect(result.nbEntities).toBe(4);
    expect(result.nbRelationships).toBe(0);

    const parsedObjects = JSON.parse(result.objects);

    // Verify formula-generated description on organization
    const orgObject = parsedObjects.find((o: any) => o.name === 'AlienVault');
    expect(orgObject).toBeDefined();
    expect(orgObject.description).toBe('Organization: AlienVault (reliability: C - Fairly reliable)');
    // Verify tools are parsed
    const tools = parsedObjects.filter((o: any) => o.type === 'tool');
    const toolNames = tools.map((o: any) => o.name);
    expect(toolNames).toContain('7-Zip');
    expect(toolNames).toContain('3proxy');
    expect(toolNames).toContain('16Shop');
    expect(tools.find((o: any) => o.name === '7-Zip')?.confidence).toBe(100);
    expect(tools.find((o: any) => o.name === '3proxy')?.confidence).toBe(75);
    expect(tools.find((o: any) => o.name === '16Shop')?.confidence).toBe(56);
  });

  it('should parse data using jsonMapperTest with extractWithRegexp formula', async () => {
    const configuration = JSON.stringify({
      name: 'Regexp Formula Mapper',
      representations: representationsRegExpr,
    });

    const fileUpload: Promise<FileUploadData> = Promise.resolve({
      createReadStream: () => Readable.from(Buffer.from(regexpTestData)),
      filename: 'regexp-test.json',
      mimeType: 'application/json',
    });

    const result = await jsonMapperTest(testContext, ADMIN_USER, configuration, fileUpload);

    expect(result).toBeDefined();
    expect(result.nbEntities).toBe(4);
    expect(result.nbRelationships).toBe(0);

    const parsedObjects = JSON.parse(result.objects);
    // Verify extractWithRegexp extracted the name before " - TXXX"
    // "CobaltStrike - T1059" -> group 1 = "CobaltStrike"
    const cobalt = parsedObjects.find((o: any) => o.name === 'CobaltStrike');
    expect(cobalt).toBeDefined();

    // "Mimikatz - S0002" -> group 1 = "Mimikatz"
    const mimi = parsedObjects.find((o: any) => o.name === 'Mimikatz');
    expect(mimi).toBeDefined();

    // "Sliver" has no " - XXXX" suffix, so extractWithRegexp returns original value
    const sliver = parsedObjects.find((o: any) => o.name === 'Sliver');
    expect(sliver).toBeDefined();

    // Verify extractWithRegexp extracted reference IDs from descriptions
    // "Reference: REF-2024-CS-001" -> group 1 = "REF-2024-CS-001"
    expect(cobalt.description).toBe('REF-2024-CS-001');

    // "Reference: REF-2023-MK-042" -> group 1 = "REF-2023-MK-042"
    expect(mimi.description).toBe('REF-2023-MK-042');

    // "No reference available." -> no match, returns original description
    expect(sliver.description).toBe('Open-source adversary emulation framework. No reference available.');
  });

  it('should stop jsonMapperTest parsing at 50 objects when input contains more records', async () => {
    const representations = [{
      id: 'tool-representation-limit-50',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_TOOL,
        path: '$.objects[?(@.type == "tool")]',
      },
      attributes: [{
        mode: 'simple',
        key: 'name',
        attr_path: { path: '$.name' },
      }],
    }];

    const toolObjects = Array.from({ length: 60 }, (_, index) => ({
      type: 'tool',
      name: `tool-${index + 1}`,
    }));

    const configuration = JSON.stringify({
      name: 'Mapper test limit to 50',
      representations,
    });

    const fileUpload: Promise<FileUploadData> = Promise.resolve({
      createReadStream: () => Readable.from(Buffer.from(JSON.stringify({ objects: toolObjects }))),
      filename: 'limit-50-test.json',
      mimeType: 'application/json',
    });

    const result = await jsonMapperTest(testContext, ADMIN_USER, configuration, fileUpload);
    const parsedObjects = JSON.parse(result.objects);

    expect(toolObjects.length).toBeGreaterThan(50);
    expect(parsedObjects).toHaveLength(50);
    expect(result.nbEntities).toBe(50);
    expect(result.nbRelationships).toBe(0);
    expect(parsedObjects[0].name).toBe('tool-1');
    expect(parsedObjects[49].name).toBe('tool-50');
    expect(parsedObjects.some((o: any) => o.name === 'tool-51')).toBe(false);
  });
});
