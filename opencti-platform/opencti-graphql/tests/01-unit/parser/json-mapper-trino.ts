import { type JsonMapperParsed, JsonMapperRepresentationType } from '../../../src/modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';

/**
  TRINO FEED SAMPLE
  No related to the test by interesting to keep for feed example usage
  export const testIngestion5: BasicStoreEntityIngestionJson = {
    id: '8f271994-a6ab-4103-97c5-561723d0a723',
    name: 'test',
    description: 'test',
    uri: 'http://localhost:8080/v1/statement',
    verb: 'post',
    body: "SELECT * FROM observables WHERE created_at > TIMESTAMP '$created' ORDER BY created_at ASC LIMIT 40",
    json_mapper_id: 'parser4',
    // ==== Specific for api that require sub queries (like trino)
    pagination_with_sub_page: true,
    pagination_with_sub_page_attribute_path: '$.nextUri',
    pagination_with_sub_page_query_verb: 'get',
    // ======================================
    confidence_to_score: true,
    authentication_type: IngestionAuthType.None,
    authentication_value: '',
    user_id: undefined,
    ingestion_running: true,
    last_execution_date: undefined,
    query_attributes: [
      {
        type: 'data', // If attribute need to be built from the response data.
        from: '$.data[(@.length-1)][6]', // Json path the get the data from the response
        to: 'created', // Name of the final param
        data_operation: 'data', // If data is an array, choose to get the size
        state_operation: 'replace', // How to manage the parameter in the state.
        default: '2025-04-26 21:55:38.240199', // Default value for the param
        exposed: 'body', // Where attribute must be exposed
      }
    ],
    // Specific headers for the query
    headers: [
      { name: 'X-Trino-User', value: 'admin' },
      { name: 'X-Trino-Schema', value: 'jri' },
      { name: 'X-Trino-Catalog', value: 'memory' }
    ]
  };
* */

export const trino_mapper: Partial<JsonMapperParsed> = {
  id: 'trino-json-mapper',
  entity_type: 'JsonMapper',
  name: 'TrinoJsonMapper',
  variables: [],
  representations: [{
    id: 'orgRepresentation',
    type: JsonMapperRepresentationType.Entity,
    target: {
      entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
      path: '$.data'
    },
    attributes: [
      {
        key: 'name',
        mode: 'simple',
        attr_path: {
          path: '$[1]',
        },
      }
    ]
  }]
};

export const trino_data = {
  id: '20250517_041959_00001_d6474',
  infoUri: 'http://localhost:8080/ui/query.html?20250517_041959_00001_d6474',
  nextUri: 'http://localhost:8080/v1/statement/executing/20250517_041959_00001_d6474/ydbb59236e398be530035721680322085678db012/2',
  columns: [
    {
      name: 'id',
      type: 'uuid',
      typeSignature: {
        rawType: 'uuid',
        arguments: []
      }
    },
    {
      name: 'md5',
      type: 'varchar',
      typeSignature: {
        rawType: 'varchar',
        arguments: [
          {
            kind: 'LONG',
            value: 2147483647
          }
        ]
      }
    },
    {
      name: 'sha1',
      type: 'varchar',
      typeSignature: {
        rawType: 'varchar',
        arguments: [
          {
            kind: 'LONG',
            value: 2147483647
          }
        ]
      }
    },
    {
      name: 'sha256',
      type: 'varchar',
      typeSignature: {
        rawType: 'varchar',
        arguments: [
          {
            kind: 'LONG',
            value: 2147483647
          }
        ]
      }
    },
    {
      name: 'sha512',
      type: 'varchar',
      typeSignature: {
        rawType: 'varchar',
        arguments: [
          {
            kind: 'LONG',
            value: 2147483647
          }
        ]
      }
    },
    {
      name: 'labels',
      type: 'array(varchar)',
      typeSignature: {
        rawType: 'array',
        arguments: [
          {
            kind: 'TYPE',
            value: {
              rawType: 'varchar',
              arguments: [
                {
                  kind: 'LONG',
                  value: 2147483647
                }
              ]
            }
          }
        ]
      }
    },
    {
      name: 'created_at',
      type: 'timestamp(6)',
      typeSignature: {
        rawType: 'timestamp',
        arguments: [
          {
            kind: 'LONG',
            value: 6
          }
        ]
      }
    }
  ],
  data: [
    [
      'ed92516d-b201-46fc-837f-67b1f069bc74',
      'd41d8cd98f00b204e9800998ecf8427e',
      'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'cf83e1357eefb8bd...',
      [
        'label1',
        'label2'
      ],
      '2023-10-01 12:00:00.000'
    ],
    [
      '0e68f057-a98e-40f3-a19d-4e2702de430b',
      'c6f0e1718c2140b348432e9b00000000',
      'b3e1e1718c2140b348432e9b00000000',
      'd3e1e1718c2140b348432e9b00000000',
      'e3e1e1718c2140b348432e9b00000000',
      [
        'label3',
        'label4'
      ],
      '2023-10-01 12:01:00.000'
    ],
    [
      '94ceabca-9294-4b0a-ba5d-d5f8f52ca15f',
      'd41d8cd98f00b204e9800998ecf8427f',
      'da39a3ee5e6b4b0d3255bfef95601890afd8070a',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856',
      'cf83e1357eefb8bd...',
      [
        'label5',
        'label6'
      ],
      '2023-10-01 12:02:00.000'
    ],
    [
      '9a85c613-bfc8-4612-871d-a992e8746e26',
      'c6f0e1718c2140b348432e9b00000001',
      'b3e1e1718c2140b348432e9b00000001',
      'd3e1e1718c2140b348432e9b00000001',
      'e3e1e1718c2140b348432e9b00000001',
      [
        'label7',
        'label8'
      ],
      '2023-10-01 12:03:00.000'
    ],
    [
      '734363a2-b32b-410f-af6b-c56b439667ca',
      'd41d8cd98f00b204e9800998ecf84280',
      'da39a3ee5e6b4b0d3255bfef95601890afd8070b',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b857',
      'cf83e1357eefb8bd...',
      [
        'label9',
        'label10'
      ],
      '2023-10-01 12:04:00.000'
    ],
    [
      'b738cc24-6bf0-48db-b8fa-4032dd16f10e',
      'c6f0e1718c2140b348432e9b00000002',
      'b3e1e1718c2140b348432e9b00000002',
      'd3e1e1718c2140b348432e9b00000002',
      'e3e1e1718c2140b348432e9b00000002',
      [
        'label11',
        'label12'
      ],
      '2023-10-01 12:05:00.000'
    ],
    [
      '2f6845e2-06fd-49d0-ba2e-abb544603ff8',
      'd41d8cd98f00b204e9800998ecf84281',
      'da39a3ee5e6b4b0d3255bfef95601890afd8070c',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b858',
      'cf83e1357eefb8bd...',
      [
        'label13',
        'label14'
      ],
      '2023-10-01 12:06:00.000'
    ],
    [
      '2715da74-6515-428e-aea6-8dbf989f306e',
      'c6f0e1718c2140b348432e9b00000003',
      'b3e1e1718c2140b348432e9b00000003',
      'd3e1e1718c2140b348432e9b00000003',
      'e3e1e1718c2140b348432e9b00000003',
      [
        'label15',
        'label16'
      ],
      '2023-10-01 12:07:00.000'
    ],
    [
      '3386b8e2-7369-4085-bd55-6ca774c17078',
      'd41d8cd98f00b204e9800998ecf84282',
      'da39a3ee5e6b4b0d3255bfef95601890afd8070d',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b859',
      'cf83e1357eefb8bd...',
      [
        'label17',
        'label18'
      ],
      '2023-10-01 12:08:00.000'
    ],
    [
      '15c571bd-f457-4841-86f3-9c1bf0ccbfc0',
      'c6f0e1718c2140b348432e9b00000004',
      'b3e1e1718c2140b348432e9b00000004',
      'd3e1e1718c2140b348432e9b00000004',
      'e3e1e1718c2140b348432e9b00000004',
      [
        'label19',
        'label20'
      ],
      '2023-10-01 12:09:00.000'
    ],
    [
      'd5389623-d140-4265-9aac-77052e57b59f',
      'd41d8cd98f00b204e9800998ecf84283',
      'da39a3ee5e6b4b0d3255bfef95601890afd8070e',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b860',
      'cf83e1357eefb8bd...',
      [
        'label21',
        'label22'
      ],
      '2023-10-01 12:10:00.000'
    ],
    [
      '0293eb2d-551b-48ff-b2ef-d06fa2dfcb4b',
      'c6f0e1718c2140b348432e9b00000005',
      'b3e1e1718c2140b348432e9b00000005',
      'd3e1e1718c2140b348432e9b00000005',
      'e3e1e1718c2140b348432e9b00000005',
      [
        'label23',
        'label24'
      ],
      '2023-10-01 12:11:00.000'
    ],
    [
      'd467e7fc-d2e3-442e-a91d-bcd949936c91',
      'd41d8cd98f00b204e9800998ecf84284',
      'da39a3ee5e6b4b0d3255bfef95601890afd8070f',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b861',
      'cf83e1357eefb8bd...',
      [
        'label25',
        'label26'
      ],
      '2023-10-01 12:12:00.000'
    ],
    [
      'ab2d7326-a66f-409c-a92c-cd9320e3cda4',
      'c6f0e1718c2140b348432e9b00000006',
      'b3e1e1718c2140b348432e9b00000006',
      'd3e1e1718c2140b348432e9b00000006',
      'e3e1e1718c2140b348432e9b00000006',
      [
        'label27',
        'label28'
      ],
      '2023-10-01 12:13:00.000'
    ],
    [
      '03b5b4d3-19d9-44e5-8830-c5bd60ec5c7f',
      'd41d8cd98f00b204e9800998ecf84285',
      'da39a3ee5e6b4b0d3255bfef95601890afd80710',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b862',
      'cf83e1357eefb8bd...',
      [
        'label29',
        'label30'
      ],
      '2023-10-01 12:14:00.000'
    ],
    [
      'cd284f62-484c-463a-987d-c44a9f20b729',
      'c6f0e1718c2140b348432e9b00000007',
      'b3e1e1718c2140b348432e9b00000007',
      'd3e1e1718c2140b348432e9b00000007',
      'e3e1e1718c2140b348432e9b00000007',
      [
        'label31',
        'label32'
      ],
      '2023-10-01 12:15:00.000'
    ],
    [
      '41d4bba7-6c1e-43bf-8500-70ceddf2e51c',
      'd41d8cd98f00b204e9800998ecf84286',
      'da39a3ee5e6b4b0d3255bfef95601890afd80711',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b863',
      'cf83e1357eefb8bd...',
      [
        'label33',
        'label34'
      ],
      '2023-10-01 12:16:00.000'
    ],
    [
      '1a7f0a58-b716-4f56-96b0-61fdc0a872df',
      'c6f0e1718c2140b348432e9b00000008',
      'b3e1e1718c2140b348432e9b00000008',
      'd3e1e1718c2140b348432e9b00000008',
      'e3e1e1718c2140b348432e9b00000008',
      [
        'label35',
        'label36'
      ],
      '2023-10-01 12:17:00.000'
    ],
    [
      'a17ed06f-7b8f-4d9e-b924-28cf47e04b0f',
      'd41d8cd98f00b204e9800998ecf84287',
      'da39a3ee5e6b4b0d3255bfef95601890afd80712',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b864',
      'cf83e1357eefb8bd...',
      [
        'label37',
        'label38'
      ],
      '2023-10-01 12:18:00.000'
    ],
    [
      'abb88b04-6ac2-4e03-af25-6d133d6b8de4',
      'c6f0e1718c2140b348432e9b00000009',
      'b3e1e1718c2140b348432e9b00000009',
      'd3e1e1718c2140b348432e9b00000009',
      'e3e1e1718c2140b348432e9b00000009',
      [
        'label39',
        'label40'
      ],
      '2023-10-01 12:19:00.000'
    ],
    [
      'c7a69f1e-3bfe-4a92-923f-c1392b66ce1d',
      'd41d8cd98f00b204e9800998ecf84288',
      'da39a3ee5e6b4b0d3255bfef95601890afd80713',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b865',
      'cf83e1357eefb8bd...',
      [
        'label41',
        'label42'
      ],
      '2023-10-01 12:20:00.000'
    ],
    [
      'aab478c0-e268-4477-8e2b-949c05ea5429',
      'c6f0e1718c2140b348432e9b00000010',
      'b3e1e1718c2140b348432e9b00000010',
      'd3e1e1718c2140b348432e9b00000010',
      'e3e1e1718c2140b348432e9b00000010',
      [
        'label43',
        'label44'
      ],
      '2023-10-01 12:21:00.000'
    ],
    [
      '0f942d57-5e7d-44c2-88b8-402aa2541cff',
      'd41d8cd98f00b204e9800998ecf84289',
      'da39a3ee5e6b4b0d3255bfef95601890afd80714',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b866',
      'cf83e1357eefb8bd...',
      [
        'label45',
        'label46'
      ],
      '2023-10-01 12:22:00.000'
    ],
    [
      '793ddd74-6ddc-4520-9789-e03575ca06d2',
      'c6f0e1718c2140b348432e9b00000011',
      'b3e1e1718c2140b348432e9b00000011',
      'd3e1e1718c2140b348432e9b00000011',
      'e3e1e1718c2140b348432e9b00000011',
      [
        'label47',
        'label48'
      ],
      '2023-10-01 12:23:00.000'
    ],
    [
      '1dd328ef-80b4-4780-81b4-7f4ad63c30be',
      'd41d8cd98f00b204e9800998ecf84290',
      'da39a3ee5e6b4b0d3255bfef95601890afd80715',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b867',
      'cf83e1357eefb8bd...',
      [
        'label49',
        'label50'
      ],
      '2023-10-01 12:24:00.000'
    ],
    [
      '42cd9ce0-87e3-4cb0-b2fa-deb5240e5cad',
      'c6f0e1718c2140b348432e9b00000012',
      'b3e1e1718c2140b348432e9b00000012',
      'd3e1e1718c2140b348432e9b00000012',
      'e3e1e1718c2140b348432e9b00000012',
      [
        'label51',
        'label52'
      ],
      '2023-10-01 12:25:00.000'
    ],
    [
      '5dc7e1be-7af9-4c13-86c2-cf4bf96dc193',
      'd41d8cd98f00b204e9800998ecf84291',
      'da39a3ee5e6b4b0d3255bfef95601890afd80716',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b868',
      'cf83e1357eefb8bd...',
      [
        'label53',
        'label54'
      ],
      '2023-10-01 12:26:00.000'
    ],
    [
      '7924288a-3663-4c68-b0c5-2eada1619c7c',
      'c6f0e1718c2140b348432e9b00000013',
      'b3e1e1718c2140b348432e9b00000013',
      'd3e1e1718c2140b348432e9b00000013',
      'e3e1e1718c2140b348432e9b00000013',
      [
        'label55',
        'label56'
      ],
      '2023-10-01 12:27:00.000'
    ],
    [
      'e1aff1c5-afc8-4d78-9cef-ed173b835823',
      'd41d8cd98f00b204e9800998ecf84292',
      'da39a3ee5e6b4b0d3255bfef95601890afd80717',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b869',
      'cf83e1357eefb8bd...',
      [
        'label57',
        'label58'
      ],
      '2023-10-01 12:28:00.000'
    ],
    [
      '5756d8a9-6132-4a5e-9c38-f3f09100e9d2',
      'c6f0e1718c2140b348432e9b00000014',
      'b3e1e1718c2140b348432e9b00000014',
      'd3e1e1718c2140b348432e9b00000014',
      'e3e1e1718c2140b348432e9b00000014',
      [
        'label59',
        'label60'
      ],
      '2023-10-01 12:29:00.000'
    ],
    [
      '91f1370f-9875-4e64-8988-345cc9a5c873',
      'd41d8cd98f00b204e9800998ecf84293',
      'da39a3ee5e6b4b0d3255bfef95601890afd80718',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b870',
      'cf83e1357eefb8bd...',
      [
        'label61',
        'label62'
      ],
      '2023-10-01 12:30:00.000'
    ],
    [
      '5ed1aa06-a3c3-4e0c-8e2a-dbf39529d57d',
      'c6f0e1718c2140b348432e9b00000015',
      'b3e1e1718c2140b348432e9b00000015',
      'd3e1e1718c2140b348432e9b00000015',
      'e3e1e1718c2140b348432e9b00000015',
      [
        'label63',
        'label64'
      ],
      '2023-10-01 12:31:00.000'
    ],
    [
      '18aa789f-b91c-4fdc-9f9d-a3658084b6b6',
      'd41d8cd98f00b204e9800998ecf84294',
      'da39a3ee5e6b4b0d3255bfef95601890afd80719',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b871',
      'cf83e1357eefb8bd...',
      [
        'label65',
        'label66'
      ],
      '2023-10-01 12:32:00.000'
    ],
    [
      '641af800-5104-43b2-b9a3-185ad4dba171',
      'c6f0e1718c2140b348432e9b00000016',
      'b3e1e1718c2140b348432e9b00000016',
      'd3e1e1718c2140b348432e9b00000016',
      'e3e1e1718c2140b348432e9b00000016',
      [
        'label67',
        'label68'
      ],
      '2023-10-01 12:33:00.000'
    ],
    [
      '686a9fec-6dac-404f-9ce3-86c638be8e7d',
      'd41d8cd98f00b204e9800998ecf84295',
      'da39a3ee5e6b4b0d3255bfef95601890afd80720',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b872',
      'cf83e1357eefb8bd...',
      [
        'label69',
        'label70'
      ],
      '2023-10-01 12:34:00.000'
    ],
    [
      '56a4f2b9-2380-4abf-84af-359aedb6e3ae',
      'c6f0e1718c2140b348432e9b00000017',
      'b3e1e1718c2140b348432e9b00000017',
      'd3e1e1718c2140b348432e9b00000017',
      'e3e1e1718c2140b348432e9b00000017',
      [
        'label71',
        'label72'
      ],
      '2023-10-01 12:35:00.000'
    ],
    [
      'ee0df25d-dd0d-4cc2-9576-1621e138ac32',
      'd41d8cd98f00b204e9800998ecf84296',
      'da39a3ee5e6b4b0d3255bfef95601890afd80721',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b873',
      'cf83e1357eefb8bd...',
      [
        'label73',
        'label74'
      ],
      '2023-10-01 12:36:00.000'
    ],
    [
      'c31d91ca-261d-424a-a332-537277c0d8e4',
      'c6f0e1718c2140b348432e9b00000018',
      'b3e1e1718c2140b348432e9b00000018',
      'd3e1e1718c2140b348432e9b00000018',
      'e3e1e1718c2140b348432e9b00000018',
      [
        'label75',
        'label76'
      ],
      '2023-10-01 12:37:00.000'
    ],
    [
      '9d83b4f0-d63a-419d-ae1c-92dab05bd3c7',
      'd41d8cd98f00b204e9800998ecf84297',
      'da39a3ee5e6b4b0d3255bfef95601890afd80722',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b874',
      'cf83e1357eefb8bd...',
      [
        'label77',
        'label78'
      ],
      '2023-10-01 12:38:00.000'
    ],
    [
      '30a36b69-ff17-4377-8bc9-a47577fe3fea',
      'c6f0e1718c2140b348432e9b00000019',
      'b3e1e1718c2140b348432e9b00000019',
      'd3e1e1718c2140b348432e9b00000019',
      'e3e1e1718c2140b348432e9b00000019',
      [
        'label79',
        'label80'
      ],
      '2023-10-01 12:39:00.000'
    ]
  ],
  stats: {
    state: 'FINISHED',
    queued: false,
    scheduled: true,
    progressPercentage: 100.0,
    runningPercentage: 0.0,
    nodes: 1,
    totalSplits: 66,
    queuedSplits: 0,
    runningSplits: 0,
    completedSplits: 66,
    planningTimeMillis: 57,
    analysisTimeMillis: 6,
    cpuTimeMillis: 68,
    wallTimeMillis: 88,
    queuedTimeMillis: 1,
    elapsedTimeMillis: 54506,
    finishingTimeMillis: 36189,
    physicalInputTimeMillis: 0,
    processedRows: 50,
    processedBytes: 10817,
    physicalInputBytes: 10817,
    physicalWrittenBytes: 0,
    internalNetworkInputBytes: 8521,
    peakMemoryBytes: 1318571,
    spilledBytes: 0,
    rootStage: {
      stageId: '0',
      state: 'FINISHED',
      done: true,
      nodes: 1,
      totalSplits: 17,
      queuedSplits: 0,
      runningSplits: 0,
      completedSplits: 17,
      cpuTimeMillis: 4,
      wallTimeMillis: 11,
      processedRows: 40,
      processedBytes: 8521,
      physicalInputBytes: 0,
      failedTasks: 0,
      coordinatorOnly: false,
      subStages: [
        {
          stageId: '1',
          state: 'FINISHED',
          done: true,
          nodes: 1,
          totalSplits: 49,
          queuedSplits: 0,
          runningSplits: 0,
          completedSplits: 49,
          cpuTimeMillis: 64,
          wallTimeMillis: 77,
          processedRows: 50,
          processedBytes: 10817,
          physicalInputBytes: 10817,
          failedTasks: 0,
          coordinatorOnly: false,
          subStages: []
        }
      ]
    }
  },
  warnings: []
};
