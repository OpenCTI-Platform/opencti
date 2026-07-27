import { JsonMapperRepresentationType } from '../../../../../src/generated/graphql';
import { ENTITY_TYPE_TOOL } from '../../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../../src/modules/organization/organization-types';

export const representationsFormulaMatrix = [
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

// JsonMapper works with any json, so it works with stix too, but stix is not mandatory.
export const stixBundleDataFormulaMatrix = JSON.stringify({
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

export const regexpTestData = JSON.stringify({
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

export const representationsRegExpr = [
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
