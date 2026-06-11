import { Readable } from 'node:stream';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { addIngestionJson, deleteIngestionJson, ingestionJsonEditField, testJsonIngestionMapping } from '../../../../src/modules/ingestion/ingestion-json-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type EditInput, IngestionAuthType, type IngestionJsonAddInput } from '../../../../src/generated/graphql';
import * as ingestionConfigMock from '../../../../src/manager/ingestionManager/ingestionManagerConfiguration';
import type { BasicStoreEntityIngestionJson } from '../../../../src/modules/ingestion/ingestion-types';
import { createJsonMapper, deleteJsonMapper, jsonMapperTest } from '../../../../src/modules/internal/jsonMapper/jsonMapper-domain';
import { JsonMapperRepresentationType } from '../../../../src/modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_TOOL } from '../../../../src/schema/stixDomainObject';
import type { FileUploadData } from '../../../../src/database/file-storage';

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
    const representations = JSON.stringify([
      {
        id: 'org-representation',
        type: JsonMapperRepresentationType.Entity,
        target: {
          entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
          path: '$.objects[?(@.type == "identity" && @.identity_class == "organization")]',
        },
        attributes: [
          {
            mode: 'simple',
            key: 'name',
            attr_path: { path: '$.name' },
          },
          {
            mode: 'complex',
            key: 'description',
            complex_path: {
              variables: [
                { variable: 'name', path: '$.name' },
                { variable: 'reliability', path: '$.x_opencti_reliability' },
              ],
              formula: '"Organization: " + name + " (reliability: " + (reliability ?? "unknown") + ")"',
            },
          },
        ],
      },
      {
        id: 'tool-representation',
        type: JsonMapperRepresentationType.Entity,
        target: {
          entity_type: ENTITY_TYPE_TOOL,
          path: '$.objects[?(@.type == "tool")]',
        },
        attributes: [
          {
            mode: 'simple',
            key: 'name',
            attr_path: { path: '$.name' },
          },
          {
            mode: 'simple',
            key: 'description',
            attr_path: { path: '$.description' },
          },
          {
            mode: 'complex',
            key: 'confidence',
            complex_path: {
              variables: [{ variable: 'conf', path: '$.confidence' }],
              formula: `decisionMatrix(conf, 50, [
                { value: 100, result: 100 },
                { value: 75, result: 75 },
                { value: 56, result: 56 },
              ])`,
            },
          },
          {
            mode: 'base',
            key: 'createdBy',
            based_on: {
              identifier: [
                { identifier: '$.created_by_ref', representation: 'org-representation' },
              ],
              representations: ['org-representation'],
            },
          },
        ],
      },
    ]);

    const input = {
      name: 'STIX Bundle Formula Mapper',
      representations,
    };

    const mapper = await createJsonMapper(testContext, ADMIN_USER, input);
    expect(mapper).toBeDefined();
    expect(mapper.id).toBeDefined();
    expect(mapper.name).toBe('STIX Bundle Formula Mapper');
    mapperId = mapper.id;
  });

  it('should parse STIX bundle data using jsonMapperTest with formulas', async () => {
    const stixBundleData = JSON.stringify({
      type: 'bundle',
      id: 'bundle--0e424850-fa12-4343-a3b8-d171ea3812fb',
      objects: [
        {
          id: 'identity--e52b2fa3-2af0-5e53-ad38-17d54b3d61cb',
          spec_version: '2.1',
          identity_class: 'organization',
          name: 'AlienVault',
          created: '2023-08-20T10:28:10.124Z',
          modified: '2026-05-08T09:53:50.980Z',
          x_opencti_organization_type: 'vendor',
          x_opencti_reliability: 'C - Fairly reliable',
          x_opencti_id: '06914efb-35f7-4387-a191-64c4bfa35c52',
          x_opencti_type: 'Organization',
          type: 'identity',
        },
        {
          id: 'tool--0b6bb549-454a-5bb5-8a58-bec1ac349d9b',
          spec_version: '2.1',
          revoked: false,
          confidence: 100,
          created: '2024-04-25T18:14:35.152Z',
          modified: '2025-12-18T19:06:51.902Z',
          name: '7-Zip',
          description: '7-Zip is a free and open-source file archiver.',
          type: 'tool',
          created_by_ref: 'identity--e52b2fa3-2af0-5e53-ad38-17d54b3d61cb',
        },
        {
          id: 'tool--94ddc726-b1b3-5c28-8b81-d632b342fff9',
          spec_version: '2.1',
          revoked: false,
          confidence: 75,
          created: '2022-08-09T15:28:07.609Z',
          modified: '2025-02-21T09:44:15.638Z',
          name: '3proxy',
          description: '3proxy is a publicly available proxy server.',
          type: 'tool',
        },
        {
          id: 'tool--dccdb7e3-a5bf-5f10-8ca2-9413c9b0ba75',
          spec_version: '2.1',
          revoked: false,
          confidence: 56,
          created: '2020-04-29T07:13:03.248Z',
          modified: '2026-04-24T12:40:52.048Z',
          name: '16Shop',
          description: '16Shop is a highly sophisticated phishing kit.',
          type: 'tool',
        },
      ],
    });

    const representations = [
      {
        id: 'org-representation',
        type: JsonMapperRepresentationType.Entity,
        target: {
          entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
          path: '$.objects[?(@.type == "identity" && @.identity_class == "organization")]',
        },
        attributes: [
          {
            mode: 'simple',
            key: 'name',
            attr_path: { path: '$.name' },
          },
          {
            mode: 'complex',
            key: 'description',
            complex_path: {
              variables: [
                { variable: 'name', path: '$.name' },
                { variable: 'reliability', path: '$.x_opencti_reliability' },
              ],
              formula: '"Organization: " + name + " (reliability: " + (reliability ?? "unknown") + ")"',
            },
          },
        ],
      },
      {
        id: 'tool-representation',
        type: JsonMapperRepresentationType.Entity,
        target: {
          entity_type: ENTITY_TYPE_TOOL,
          path: '$.objects[?(@.type == "tool")]',
        },
        attributes: [
          {
            mode: 'simple',
            key: 'name',
            attr_path: { path: '$.name' },
          },
          {
            mode: 'simple',
            key: 'description',
            attr_path: { path: '$.description' },
          },
          {
            mode: 'complex',
            key: 'confidence',
            complex_path: {
              variables: [{ variable: 'conf', path: '$.confidence' }],
              formula: `decisionMatrix(conf, 50, [
                { value: 100, result: 100 },
                { value: 75, result: 75 },
                { value: 56, result: 56 },
              ])`,
            },
          },
          {
            mode: 'base',
            key: 'createdBy',
            based_on: {
              identifier: [
                { identifier: '$.created_by_ref', representation: 'org-representation' },
              ],
              representations: ['org-representation'],
            },
          },
        ],
      },
    ];

    const configuration = JSON.stringify({
      name: 'STIX Bundle Formula Mapper',
      representations,
    });

    const fileUpload: Promise<FileUploadData> = Promise.resolve({
      createReadStream: () => Readable.from(Buffer.from(stixBundleData)),
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
    expect(parsedObjects.length).toBe(4);

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

  it('should parse data using jsonMapperTest with extractWithRegexp formula', async () => {
    // Data with names that contain structured patterns suitable for regex extraction
    // Format: "MalwareName - V123" where we want to extract just the malware name
    const regexpTestData = JSON.stringify({
      type: 'bundle',
      id: 'bundle--aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee',
      objects: [
        {
          id: 'tool--1111aaaa-2222-3333-4444-555566667777',
          spec_version: '2.1',
          revoked: false,
          confidence: 80,
          created: '2024-01-01T00:00:00.000Z',
          modified: '2024-06-01T00:00:00.000Z',
          name: 'CobaltStrike - T1059',
          description: 'CobaltStrike beacon used for post-exploitation. Reference: REF-2024-CS-001',
          type: 'tool',
        },
        {
          id: 'tool--2222bbbb-3333-4444-5555-666677778888',
          spec_version: '2.1',
          revoked: false,
          confidence: 90,
          created: '2024-02-15T00:00:00.000Z',
          modified: '2024-07-01T00:00:00.000Z',
          name: 'Mimikatz - S0002',
          description: 'Credential dumping tool. Reference: REF-2023-MK-042',
          type: 'tool',
        },
        {
          id: 'tool--3333cccc-4444-5555-6666-777788889999',
          spec_version: '2.1',
          revoked: false,
          confidence: 70,
          created: '2024-03-20T00:00:00.000Z',
          modified: '2024-08-01T00:00:00.000Z',
          name: 'Sliver',
          description: 'Open-source adversary emulation framework. No reference available.',
          type: 'tool',
        },
        {
          id: 'tool--3333cccc-4444-5555-6666-777788881234',
          spec_version: '2.1',
          revoked: false,
          confidence: 70,
          created: '2024-03-20T00:00:00.000Z',
          modified: '2024-08-01T00:00:00.000Z',
          name: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab',
          description: 'Very strange tool name',
          type: 'tool',
        },
      ],
    });

    const representations = [
      {
        id: 'tool-with-regexp',
        type: JsonMapperRepresentationType.Entity,
        target: {
          entity_type: ENTITY_TYPE_TOOL,
          path: '$.objects[?(@.type == "tool")]',
        },
        attributes: [
          {
            // Use extractWithRegexp to extract just the tool name (before " - ")
            // Pattern: "CobaltStrike - T1059" -> captures "CobaltStrike"
            mode: 'complex',
            key: 'name',
            complex_path: {
              variables: [{ variable: 'name', path: '$.name' }],
              formula: 'extractWithRegexp("(.*)( - )([A-Z][0-9]{1,})", 1, name)',
            },
          },
          {
            // Use extractWithRegexp to extract reference ID from description
            // Pattern: "Reference: REF-2024-CS-001" -> captures "REF-2024-CS-001"
            mode: 'complex',
            key: 'description',
            complex_path: {
              variables: [{ variable: 'desc', path: '$.description' }],
              formula: 'extractWithRegexp("Reference: (REF-[A-Z0-9-]+)", 1, desc)',
            },
          },
        ],
      },
    ];

    const configuration = JSON.stringify({
      name: 'Regexp Formula Mapper',
      representations,
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
    expect(parsedObjects.length).toBe(4);

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
});
