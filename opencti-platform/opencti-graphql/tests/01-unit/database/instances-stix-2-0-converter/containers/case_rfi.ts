import type { StoreEntityCaseRfi2 } from '../../../../../src/modules/case/case-rfi/case-rfi-types';

export const RFI_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: '4ebd03f2-d922-4449-915e-2facb67e781c',
  id: '4ebd03f2-d922-4449-915e-2facb67e781c',
  sort: [
    1750960290746
  ],
  name: 'RFI STIX 2.0',
  description: 'description',
  content: '<p>some content:&nbsp;</p><div style="-webkit-text-stroke-width:0px;align-items:center;background-color:rgb(7, 13, 25);box-sizing:inherit;color:rgb(255, 255, 255);display:flex;font-family:&quot;IBM Plex Sans&quot;, sans-serif;font-size:14.4px;font-style:normal;font-variant-caps:normal;font-variant-ligatures:normal;font-weight:400;gap:8px;letter-spacing:normal;orphans:2;scrollbar-width:thin;text-align:start;text-decoration-color:initial;text-decoration-style:initial;text-decoration-thickness:initial;text-indent:0px;text-transform:none;white-space:normal;widows:2;word-spacing:0px;"><h1 style="margin-left:0px;">Paradise Ransomware</h1><div style="align-items:center;box-sizing:inherit;display:flex;scrollbar-width:thin;">&nbsp;</div></div><div style="-webkit-text-stroke-width:0px;align-items:center;background-color:rgb(7, 13, 25);box-sizing:inherit;color:rgb(255, 255, 255);display:flex;font-family:&quot;IBM Plex Sans&quot;, sans-serif;font-size:14.4px;font-style:normal;font-variant-caps:normal;font-variant-ligatures:normal;font-weight:400;letter-spacing:normal;orphans:2;scrollbar-width:thin;text-align:start;text-decoration-color:initial;text-decoration-style:initial;text-decoration-thickness:initial;text-indent:0px;text-transform:none;white-space:normal;widows:2;word-spacing:0px;"><div style="box-sizing:inherit;display:flex;scrollbar-width:thin;"><br>&nbsp;</div></div>',
  severity: 'medium',
  priority: 'P2',
  confidence: 100,
  created: '2025-06-26T17:50:38.000Z',
  information_types: [
    'type 1'
  ],
  entity_type: 'Case-Rfi',
  internal_id: '4ebd03f2-d922-4449-915e-2facb67e781c',
  standard_id: 'case-rfi--cc1229b2-8ba7-50fd-b822-055b45e3aa4f',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T17:51:30.746Z',
  updated_at: '2025-06-26T17:52:57.246Z',
  revoked: false,
  lang: 'en',
  modified: '2025-06-26T17:52:57.246Z',
  x_opencti_workflow_id: '38f497dc-b0bc-48e5-aff8-0e5bd5d5937a',
  base_type: 'ENTITY',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Domain-Object',
    'Container',
    'Case'
  ],
  x_opencti_files: [
    {
      id: 'import/Case-Rfi/4ebd03f2-d922-4449-915e-2facb67e781c/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T17:51:30.748Z',
      mime_type: 'application/json',
      file_markings: [
        '2cc876e4-ae90-497b-a4ae-16c762f0d03f'
      ],
      objectMarking: [
        {
          _index: 'opencti_stix_meta_objects-000001',
          _id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
          id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
          sort: [
            1749546753947
          ],
          entity_type: 'Marking-Definition',
          internal_id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
          standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
          base_type: 'ENTITY'
        }
      ]
    }
  ],
  i_attributes: [
    {
      updated_at: '2025-06-26T17:52:57.221Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objects'
    },
    {
      updated_at: '2025-06-26T17:52:32.332Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'content'
    },
    {
      updated_at: '2025-06-26T17:52:39.133Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'content_mapping'
    }
  ],
  content_mapping: 'eyJwYXJhZGlzZSByYW5zb213YXJlIjoibWFsd2FyZS0tMjFjNDVkYmUtNTRlYy01YmI3LWI4Y2QtOWYyN2NjNTE4NzE0In0',
  object: [
    '64450249-69b4-43ac-816a-da6721ac1fce',
    'c808561d-ed59-4d54-914a-5d090eceafd6',
    '2e4b754a-9990-4ddb-89a4-527f18368f9b',
    'dce63edb-533e-4ca5-9d00-f88c51aff6fb'
  ],
  objects: [
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: '64450249-69b4-43ac-816a-da6721ac1fce',
      id: '64450249-69b4-43ac-816a-da6721ac1fce',
      sort: [
        1749547858694
      ],
      x_opencti_stix_ids: [
        'campaign--d02a1560-ff69-49f4-ac34-919b8aa4b91e'
      ],
      name: 'th3bug',
      description: 'This ongoing campaign targets a number of industries but appears to prefer targets in higher education and the healthcare sectors.',
      aliases: null,
      revoked: false,
      lang: 'en',
      confidence: 100,
      first_seen: '2009-10-26T00:00:00.000Z',
      last_seen: '5138-11-16T09:46:40.000Z',
      objective: null,
      created: '2015-05-15T09:12:16.432Z',
      modified: '2015-05-15T09:12:16.432Z',
      x_opencti_workflow_id: null,
      entity_type: 'Campaign',
      internal_id: '64450249-69b4-43ac-816a-da6721ac1fce',
      standard_id: 'campaign--e388a843-1590-5af1-b5a5-50231c97cfba',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:30:58.694Z',
      updated_at: '2025-06-10T09:30:58.694Z',
      i_aliases_ids: [],
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Domain-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'f54ca040-290f-49c0-9d9c-cbbd2bd0752c',
        id: 'f54ca040-290f-49c0-9d9c-cbbd2bd0752c',
        sort: [
          'relationship-meta--13ab7304-728a-4bac-8c84-dcaa357407a4'
        ],
        base_type: 'RELATION',
        internal_id: 'f54ca040-290f-49c0-9d9c-cbbd2bd0752c',
        standard_id: 'relationship-meta--13ab7304-728a-4bac-8c84-dcaa357407a4',
        entity_type: 'object',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'object_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: '64450249-69b4-43ac-816a-da6721ac1fce',
        toRole: 'object_to',
        toName: 'th3bug',
        toType: 'Campaign',
        target_ref: 'campaign--temporary',
        relationship_type: 'object'
      }
    },
    {
      _index: 'opencti_stix_cyber_observables-000001',
      _id: 'c808561d-ed59-4d54-914a-5d090eceafd6',
      id: 'c808561d-ed59-4d54-914a-5d090eceafd6',
      sort: [
        1749548017333
      ],
      x_opencti_score: 50,
      x_opencti_description: 'Basic credential',
      value: 'azerty',
      confidence: 100,
      entity_type: 'Credential',
      internal_id: 'c808561d-ed59-4d54-914a-5d090eceafd6',
      standard_id: 'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      x_opencti_stix_ids: [
        'credential--8e0a834a-c233-5c50-8186-adde10a69f02'
      ],
      created_at: '2025-06-10T09:33:37.333Z',
      updated_at: '2025-06-10T09:33:37.345Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Cyber-Observable'
      ],
      modified: '2025-06-10T09:33:37.345Z',
      draft_ids: [
        '2c0ff00c-f892-4f22-b863-58de30313461'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'a7bccd0b-54b3-4fbc-b381-a18c426167ec',
        id: 'a7bccd0b-54b3-4fbc-b381-a18c426167ec',
        sort: [
          'relationship-meta--21fa7057-8d9d-48b1-9824-97ccd12b401f'
        ],
        base_type: 'RELATION',
        internal_id: 'a7bccd0b-54b3-4fbc-b381-a18c426167ec',
        standard_id: 'relationship-meta--21fa7057-8d9d-48b1-9824-97ccd12b401f',
        entity_type: 'object',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'object_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: 'c808561d-ed59-4d54-914a-5d090eceafd6',
        toRole: 'object_to',
        toName: 'azerty',
        toType: 'Credential',
        target_ref: 'credential--temporary',
        relationship_type: 'object'
      }
    },
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: '2e4b754a-9990-4ddb-89a4-527f18368f9b',
      id: '2e4b754a-9990-4ddb-89a4-527f18368f9b',
      sort: [
        1749547951501
      ],
      x_opencti_stix_ids: [
        'incident--0b626d41-1d8d-4b96-86fa-ad49cea2cfd4'
      ],
      name: 'A new incident',
      description: 'A test incident',
      confidence: 100,
      revoked: false,
      lang: 'en',
      objective: null,
      first_seen: '2020-02-27T08:45:47.779Z',
      last_seen: '2020-02-27T08:45:47.779Z',
      aliases: null,
      incident_type: null,
      severity: null,
      source: null,
      created: '2020-03-25T14:48:31.601Z',
      modified: '2025-06-10T09:34:51.852Z',
      x_opencti_workflow_id: null,
      entity_type: 'Incident',
      internal_id: '2e4b754a-9990-4ddb-89a4-527f18368f9b',
      standard_id: 'incident--8658860d-df08-5f41-bf41-106095e48085',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:32:31.501Z',
      updated_at: '2025-06-10T09:34:51.852Z',
      i_aliases_ids: [],
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Domain-Object'
      ],
      opinions_metrics: {
        total: 1,
        min: 5,
        max: 5,
        mean: 5
      },
      i_attributes: [
        {
          updated_at: '2025-06-10T09:34:51.852Z',
          user_id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
          confidence: 100,
          name: 'opinions_metrics'
        }
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '0d62caa1-5c05-4822-82e3-66e3e073737d',
        id: '0d62caa1-5c05-4822-82e3-66e3e073737d',
        sort: [
          'relationship-meta--926427db-688a-4084-82ed-7c88dc7c3f84'
        ],
        base_type: 'RELATION',
        internal_id: '0d62caa1-5c05-4822-82e3-66e3e073737d',
        standard_id: 'relationship-meta--926427db-688a-4084-82ed-7c88dc7c3f84',
        entity_type: 'object',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'object_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: '2e4b754a-9990-4ddb-89a4-527f18368f9b',
        toRole: 'object_to',
        toName: 'A new incident',
        toType: 'Incident',
        target_ref: 'incident--temporary',
        relationship_type: 'object'
      }
    },
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: 'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
      id: 'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
      sort: [
        1749547881666
      ],
      x_opencti_stix_ids: [
        'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c'
      ],
      name: 'Paradise Ransomware',
      description: 'MalwareHunterTeam discovered a new Paradise Ransomware variant that uses the extension _V.0.0.0.1{paradise@all-ransomware.info}.prt and drops a ransom note named PARADISE_README_paradise@all-ransomware.info.txt.',
      malware_types: null,
      aliases: null,
      is_family: false,
      first_seen: '1970-01-01T00:00:00.000Z',
      last_seen: '5138-11-16T09:46:40.000Z',
      architecture_execution_envs: null,
      implementation_languages: null,
      capabilities: null,
      confidence: 100,
      revoked: false,
      lang: 'en',
      created: '2019-09-30T16:38:26.000Z',
      modified: '2025-06-10T09:34:55.065Z',
      x_opencti_workflow_id: null,
      entity_type: 'Malware',
      internal_id: 'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
      standard_id: 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:31:21.666Z',
      updated_at: '2025-06-10T09:34:55.065Z',
      i_aliases_ids: [],
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Domain-Object'
      ],
      opinions_metrics: {
        total: 1,
        min: 5,
        max: 5,
        mean: 5
      },
      i_attributes: [
        {
          updated_at: '2025-06-10T09:34:55.065Z',
          user_id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
          confidence: 100,
          name: 'opinions_metrics'
        }
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'ec599d15-bcab-4648-9077-b09f3bd69d2b',
        id: 'ec599d15-bcab-4648-9077-b09f3bd69d2b',
        sort: [
          'relationship-meta--c486ac76-37ca-437c-b5df-cb7b2180ae7b'
        ],
        base_type: 'RELATION',
        internal_id: 'ec599d15-bcab-4648-9077-b09f3bd69d2b',
        standard_id: 'relationship-meta--c486ac76-37ca-437c-b5df-cb7b2180ae7b',
        entity_type: 'object',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'object_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: 'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
        toRole: 'object_to',
        toName: 'Paradise Ransomware',
        toType: 'Malware',
        target_ref: 'malware--temporary',
        relationship_type: 'object'
      }
    }
  ],
  'external-reference': [
    '746847b8-f5d0-4c82-a7a2-70649ac9b135'
  ],
  externalReferences: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
      id: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
      sort: [
        1749547864832
      ],
      x_opencti_stix_ids: [],
      source_name: 'capec',
      description: 'spear phishing',
      url: null,
      external_id: 'CAPEC-163',
      created: '2025-06-10T09:31:04.832Z',
      modified: '2025-06-10T09:31:04.832Z',
      confidence: 100,
      entity_type: 'External-Reference',
      internal_id: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
      standard_id: 'external-reference--4a67461d-68b8-5a27-996f-a8e30578cb56',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:31:04.832Z',
      updated_at: '2025-06-10T09:31:04.832Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'dcd28a7e-f824-4801-b194-2db4a3fbfcb2',
        id: 'dcd28a7e-f824-4801-b194-2db4a3fbfcb2',
        sort: [
          'relationship-meta--1989a1e1-addd-444a-99cc-f67f61d6ef0c'
        ],
        base_type: 'RELATION',
        internal_id: 'dcd28a7e-f824-4801-b194-2db4a3fbfcb2',
        standard_id: 'relationship-meta--1989a1e1-addd-444a-99cc-f67f61d6ef0c',
        entity_type: 'external-reference',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'external-reference_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
        toRole: 'external-reference_to',
        toName: 'capec (CAPEC-163)',
        toType: 'External-Reference',
        target_ref: 'external-reference--temporary',
        relationship_type: 'external-reference'
      }
    }
  ],
  'created-by': '0097209b-e5d7-43f2-b901-cf665df73f6b',
  createdBy: {
    _index: 'opencti_stix_domain_objects-000001',
    _id: '0097209b-e5d7-43f2-b901-cf665df73f6b',
    id: '0097209b-e5d7-43f2-b901-cf665df73f6b',
    sort: [
      1749548300272
    ],
    name: 'admin',
    contact_information: 'admin@opencti.io',
    identity_class: 'individual',
    confidence: 100,
    entity_type: 'Individual',
    internal_id: '0097209b-e5d7-43f2-b901-cf665df73f6b',
    standard_id: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
    creator_id: [
      '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
    ],
    x_opencti_stix_ids: [],
    created_at: '2025-06-10T09:38:20.272Z',
    updated_at: '2025-06-10T09:38:28.303Z',
    revoked: false,
    lang: 'en',
    created: '2025-06-10T09:38:20.272Z',
    modified: '2025-06-10T09:38:28.303Z',
    i_aliases_ids: [],
    base_type: 'ENTITY',
    parent_types: [
      'Basic-Object',
      'Stix-Object',
      'Stix-Core-Object',
      'Stix-Domain-Object',
      'Identity'
    ],
    x_opencti_firstname: 'Admin',
    x_opencti_lastname: 'OpenCTI',
    i_attributes: [
      {
        updated_at: '2025-06-10T09:38:28.303Z',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        confidence: 100,
        name: 'x_opencti_firstname'
      },
      {
        updated_at: '2025-06-10T09:38:28.303Z',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        confidence: 100,
        name: 'x_opencti_lastname'
      }
    ],
    i_relation: {
      _index: 'opencti_stix_meta_relationships-000001',
      _id: '0c813f8c-b094-488f-96ae-3a9d12959f17',
      id: '0c813f8c-b094-488f-96ae-3a9d12959f17',
      sort: [
        'relationship-meta--43ada8de-f276-4265-bfc9-fef96e97abdb'
      ],
      base_type: 'RELATION',
      internal_id: '0c813f8c-b094-488f-96ae-3a9d12959f17',
      standard_id: 'relationship-meta--43ada8de-f276-4265-bfc9-fef96e97abdb',
      entity_type: 'created-by',
      from: null,
      fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
      fromRole: 'created-by_from',
      fromName: 'RFI STIX 2.0',
      fromType: 'Case-Rfi',
      source_ref: 'case-rfi--temporary',
      to: null,
      toId: '0097209b-e5d7-43f2-b901-cf665df73f6b',
      toRole: 'created-by_to',
      toName: 'admin',
      toType: 'Individual',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  },
  'object-participant': [
    '0ff0750e-4d91-425d-b44c-b69269dead0b'
  ],
  objectParticipant: [
    {
      _index: 'opencti_internal_objects-000001',
      _id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      sort: [
        1750152527269
      ],
      user_email: 'marie.flores@filigran.io',
      name: 'marie',
      password: '$2a$10$GElYhi3IFp7bSu6jYNz/JO4tCVNWr6tVEXJXLr/npfbS.EYu/8YlC',
      firstname: '',
      lastname: '',
      description: '',
      account_status: 'Active',
      account_lock_after_date: null,
      user_confidence_level: null,
      api_token: 'dfd7ed5d-5374-4a2e-a088-4a4c0013ccd7',
      theme: 'default',
      language: 'auto',
      external: false,
      personal_notifiers: [
        'f4ee7b33-006a-4b0d-b57d-411ad288653d',
        '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'
      ],
      confidence: 100,
      entity_type: 'User',
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-17T09:28:47.269Z',
      updated_at: '2025-06-17T09:28:47.332Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Internal-Object'
      ],
      modified: '2025-06-17T09:28:47.332Z',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '05d0c227-d413-4f8d-9748-a935afa4ad58',
        id: '05d0c227-d413-4f8d-9748-a935afa4ad58',
        sort: [
          'relationship-meta--4c618180-91d6-4473-997c-0b5b984a0a30'
        ],
        base_type: 'RELATION',
        internal_id: '05d0c227-d413-4f8d-9748-a935afa4ad58',
        standard_id: 'relationship-meta--4c618180-91d6-4473-997c-0b5b984a0a30',
        entity_type: 'object-participant',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'object-participant_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: '0ff0750e-4d91-425d-b44c-b69269dead0b',
        toRole: 'object-participant_to',
        toName: 'marie',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-participant'
      }
    }
  ],
  'object-marking': [
    '2cc876e4-ae90-497b-a4ae-16c762f0d03f'
  ],
  objectMarking: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
      id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
      sort: [
        1749546753947
      ],
      definition_type: 'PAP',
      definition: 'PAP:CLEAR',
      x_opencti_color: '#ffffff',
      x_opencti_order: 1,
      confidence: 100,
      entity_type: 'Marking-Definition',
      internal_id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
      standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      creator_id: [
        '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
      ],
      x_opencti_stix_ids: [],
      created_at: '2025-06-10T09:12:33.947Z',
      updated_at: '2025-06-10T09:12:33.947Z',
      created: '2025-06-10T09:12:33.947Z',
      modified: '2025-06-10T09:12:33.947Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '1183bfbe-dfed-4d79-9bd1-5becbd880fe3',
        id: '1183bfbe-dfed-4d79-9bd1-5becbd880fe3',
        sort: [
          'relationship-meta--a8870308-a997-4a09-9e4a-cabcbc95729c'
        ],
        base_type: 'RELATION',
        internal_id: '1183bfbe-dfed-4d79-9bd1-5becbd880fe3',
        standard_id: 'relationship-meta--a8870308-a997-4a09-9e4a-cabcbc95729c',
        entity_type: 'object-marking',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'object-marking_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
        toRole: 'object-marking_to',
        toName: 'PAP:CLEAR',
        toType: 'Marking-Definition',
        target_ref: 'marking-definition--temporary',
        relationship_type: 'object-marking'
      }
    }
  ],
  'object-assignee': [
    '0ff0750e-4d91-425d-b44c-b69269dead0b'
  ],
  objectAssignee: [
    {
      _index: 'opencti_internal_objects-000001',
      _id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      sort: [
        1750152527269
      ],
      user_email: 'marie.flores@filigran.io',
      name: 'marie',
      password: '$2a$10$GElYhi3IFp7bSu6jYNz/JO4tCVNWr6tVEXJXLr/npfbS.EYu/8YlC',
      firstname: '',
      lastname: '',
      description: '',
      account_status: 'Active',
      account_lock_after_date: null,
      user_confidence_level: null,
      api_token: 'dfd7ed5d-5374-4a2e-a088-4a4c0013ccd7',
      theme: 'default',
      language: 'auto',
      external: false,
      personal_notifiers: [
        'f4ee7b33-006a-4b0d-b57d-411ad288653d',
        '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'
      ],
      confidence: 100,
      entity_type: 'User',
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-17T09:28:47.269Z',
      updated_at: '2025-06-17T09:28:47.332Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Internal-Object'
      ],
      modified: '2025-06-17T09:28:47.332Z',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '27db37ad-da3a-490d-be6a-84cbc70438f2',
        id: '27db37ad-da3a-490d-be6a-84cbc70438f2',
        sort: [
          'relationship-meta--dd13a188-3d82-49d9-b762-a6c290edd2d8'
        ],
        base_type: 'RELATION',
        internal_id: '27db37ad-da3a-490d-be6a-84cbc70438f2',
        standard_id: 'relationship-meta--dd13a188-3d82-49d9-b762-a6c290edd2d8',
        entity_type: 'object-assignee',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'object-assignee_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: '0ff0750e-4d91-425d-b44c-b69269dead0b',
        toRole: 'object-assignee_to',
        toName: 'marie',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-assignee'
      }
    }
  ],
  'object-label': [
    'd6d10328-9d53-4da8-af37-fb859cbbc693'
  ],
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: 'd6d10328-9d53-4da8-af37-fb859cbbc693',
      id: 'd6d10328-9d53-4da8-af37-fb859cbbc693',
      sort: [
        1749547953634
      ],
      x_opencti_stix_ids: [],
      value: 'ryuk',
      color: '#1da735',
      confidence: 100,
      entity_type: 'Label',
      internal_id: 'd6d10328-9d53-4da8-af37-fb859cbbc693',
      standard_id: 'label--66b4d95f-ba1a-54b3-b5a3-74c7fb93142b',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:32:33.634Z',
      updated_at: '2025-06-10T09:32:33.634Z',
      created: '2025-06-10T09:32:33.634Z',
      modified: '2025-06-10T09:32:33.634Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'd75936b6-d27b-4126-8319-1cce9094f3db',
        id: 'd75936b6-d27b-4126-8319-1cce9094f3db',
        sort: [
          'relationship-meta--f144cc75-5802-4066-b8fb-65c96737e936'
        ],
        base_type: 'RELATION',
        internal_id: 'd75936b6-d27b-4126-8319-1cce9094f3db',
        standard_id: 'relationship-meta--f144cc75-5802-4066-b8fb-65c96737e936',
        entity_type: 'object-label',
        from: null,
        fromId: '4ebd03f2-d922-4449-915e-2facb67e781c',
        fromRole: 'object-label_from',
        fromName: 'RFI STIX 2.0',
        fromType: 'Case-Rfi',
        source_ref: 'case-rfi--temporary',
        to: null,
        toId: 'd6d10328-9d53-4da8-af37-fb859cbbc693',
        toRole: 'object-label_to',
        toName: 'ryuk',
        toType: 'Label',
        target_ref: 'label--temporary',
        relationship_type: 'object-label'
      }
    }
  ]
} as unknown as StoreEntityCaseRfi2;

export const EXPECTED_RFI = {
  id: 'x-opencti-case-rfi--cc1229b2-8ba7-50fd-b822-055b45e3aa4f',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T17:50:38.000Z',
  modified: '2025-06-26T17:52:57.246Z',
  name: 'RFI STIX 2.0',
  description: 'description',
  information_types: [
    'type 1'
  ],
  severity: 'medium',
  priority: 'P2',
  x_opencti_workflow_id: '38f497dc-b0bc-48e5-aff8-0e5bd5d5937a',
  labels: [
    'ryuk'
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163'
    }
  ],
  x_opencti_id: '4ebd03f2-d922-4449-915e-2facb67e781c',
  x_opencti_type: 'Case-Rfi',
  type: 'x-opencti-case-rfi',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  object_refs: [
    'campaign--e388a843-1590-5af1-b5a5-50231c97cfba',
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
    'incident--8658860d-df08-5f41-bf41-106095e48085',
    'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Case-Rfi/4ebd03f2-d922-4449-915e-2facb67e781c/ipv4_example.json',
      version: '2025-06-26T17:51:30.748Z',
    },
  ],
  x_opencti_granted_refs: [],
};
