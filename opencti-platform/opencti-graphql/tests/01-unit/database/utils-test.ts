import { afterEach, describe, expect, it } from 'vitest';
import { extractObjectsPirsFromInputs, extractObjectsRestrictionsFromInputs, fillTimeSeries } from '../../../src/database/utils';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { EditOperation } from '../../../src/generated/graphql';

const inputs = [
  {
    key: 'objects',
    operation: EditOperation.Add,
    value: [
      {
        _id: '4c688965-fd97-40ea-9af0-967030eb06a5',
        _index: 'opencti_stix_domain_objects-000001',
        aliases: [],
        base_type: 'ENTITY',
        confidence: 100,
        created: '2024  -11-08T10:30:44.343Z',
        'created-by': 'bc9fe33d-e694-4604-abc1-82f2e99cd00a',
        created_at: '2024-12-02T13:55:39.981Z',
        creator_id: [
          '549e078a-41df-43aa-8e0f-ba961b16d0c8'
        ],
        description: '',
        entity_type: 'Intrusion-Set',
        'external-reference': [],
        first_seen: '1970-01-01T00:00:00.000Z',
        goals: ['Military Advantage'],
        i_aliases_ids: [],
        id: '4c688965-fd97-40ea-9af0-967030eb06a5',
        internal_id: '4c688965-fd97-40ea-9af0-967030eb06a5',
        lang: 'en',
        last_seen: '5138-11-16T09:46:40.000Z',
        modified: '2024-12-02T13:55:40.064Z',
        name: 'APT29',
        'object-label': [
          'debcc53e-9515-4107-bbdc-8eb8084f7527'
        ],
        'object-marking': [
          'fa7fa933-7b65-463f-ac5e-aa33b2a36ce8',
          '056276ff-26dc-4774-a439-a36253a96939'
        ],
        parent_types: [
          'Basic-Object',
          'Stix-Object',
          'Stix-Core-Object',
          'Stix-Domain-Object'
        ],
        primary_motivation: 'Espionage',
        'rel_created-by.internal_id': [
          'bc9fe33d-e694-4604-abc1-82f2e99cd00a'
        ],
        'rel_external-reference.internal_id': [],
        'rel_object-label.internal_id': [
          'debcc53e-9515-4107-bbdc-8eb8084f7527'
        ],
        'rel_object-marking.internal_id': [
          'fa7fa933-7b65-463f-ac5e-aa33b2a36ce8',
          '056276ff-26dc-4774-a439-a36253a96939'
        ],
        resource_level: null,
        revoked: false,
        'secondary_motivation  s': [
          'Military/Security/Diplomatic',
          'Ethnic/nationalist',
          'Ideological/Religious'
        ],
        sort: [
          1733147739981
        ],
        standard_id: 'intrusion-set--36319194-19e1-50ac-9163-778b56a1bf12',
        updated_at: '2024-12-02T13:55:40.064Z',
        x_opencti_stix_ids: [],
        x_opencti_workflow_id: null
      }
    ]
  }
];

const relInputs = [
  {
    key: 'objects',
    operation: EditOperation.Add,
    value: [
      {
        _id: '23c0c086-afee-45e5-b276-872948997816',
        _index: 'opencti_stix_core_relationships-000001',
        base_type: 'RELATION',
        confidence: 100,
        created: '2024-12-0  6T08:41:59.270Z',
        created_at: '2024-12-06T08:41:59.270Z',
        creator_id: [
          '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
        ],
        description: '',
        entity_type: 'related-to',
        from: null,
        fromId: 'fd3259cb-f219-4cd6-85fe-0df16ffef185',
        fromName: 'AlienVault',
        fromRole: 'related-to_from',
        fromType: 'Organization',
        id: '23c0c086-afee-45e5-b276-872948997816',
        internal_id: '23c0c086-afee-45e5-b276-872948997816',
        lang: 'en',
        modified: '2024-12-06T08:41:59.290Z',
        'object-marking': [
          'eaccd139-ec2e-48d9-b2ef-a17ba6e7e938'
        ],
        parent_types: [
          'basic-relationship',
          'stix-relationship',
          'stix-core-relationship'
        ],
        'rel_object-marking.internal_id': [
          'eaccd139-ec2e-48d9-b2ef-a17ba6e7e938'
        ],
        relationship_type: 'related-to',
        revoked: false,
        sort: [
          1733474519270
        ],
        source_ref: 'identity--temporary',
        standard_id: 'relationship--54af1a95-b0e8-53d6-8c0c-074f57e9d58c',
        start_time: '2024-12-06T08:40:55.000Z',
        stop_time: '2024-12-06T08:41:55.000Z',
        target_ref: 'malware--temporary',
        to: null,
        toId: 'd9162b45-55dd-403b-906b-a16edf74ebff',
        toName: 'HAMMERTOSS',
        toRole: 'related-to_to',
        toType: 'Malware',
        updated_at: '2024-12-06T08:41:59.290Z',
        x_opencti_stix_ids: []
      }
    ]
  }
];

describe('extractObjectsRestrictionsFromInputs testing', () => {
  it('should add inputs object-marking in stream when adding entity to a report', () => {
    const relatedRestrictions = extractObjectsRestrictionsFromInputs(inputs, ENTITY_TYPE_CONTAINER_REPORT);
    const expected = { markings: ['fa7fa933-7b65-463f-ac5e-aa33b2a36ce8', '056276ff-26dc-4774-a439-a36253a96939'] };
    expect(relatedRestrictions).toEqual(expected);
  });
  it('should add inputs object-marking in stream when adding relationship to a report', () => {
    const relatedRestrictions = extractObjectsRestrictionsFromInputs(relInputs, ENTITY_TYPE_CONTAINER_REPORT);
    const expected = { markings: ['eaccd139-ec2e-48d9-b2ef-a17ba6e7e938'] };
    expect(relatedRestrictions).toEqual(expected);
  });
  it('should not add inputs object-marking in stream if entity is not container', () => {
    const relatedRestrictions = extractObjectsRestrictionsFromInputs(inputs, ENTITY_TYPE_MALWARE);
    const expected = { markings: [] };
    expect(relatedRestrictions).toEqual(expected);
  });
});

describe('Function extractObjectsPirsFromInputs()', () => {
  const baseInputs = [{
    key: 'objects',
    operation: EditOperation.Add,
    value: [{ confidence: 100 }]
  }];
  const pirInputs = [{
    key: 'objects',
    operation: EditOperation.Add,
    value: [{ confidence: 100, 'in-pir': ['pir1', 'pir2', 'pir3'] }]
  }];

  it('should return PIR ids in Report', () => {
    const { pir_ids } = extractObjectsPirsFromInputs(pirInputs, ENTITY_TYPE_CONTAINER_REPORT);
    expect(pir_ids).toEqual(['pir1', 'pir2', 'pir3']);
  });

  it('should return empty array in Report if no PIR ids', () => {
    const { pir_ids } = extractObjectsPirsFromInputs(baseInputs, ENTITY_TYPE_CONTAINER_REPORT);
    expect(pir_ids).toEqual([]);
  });

  it('should return empty array if not a container', () => {
    const { pir_ids } = extractObjectsPirsFromInputs(pirInputs, ENTITY_TYPE_MALWARE);
    expect(pir_ids).toEqual([]);
  });
});

describe('Function fillTimeSeries()', () => {
  // The process time zone must never leak into the emitted buckets: Elasticsearch
  // aggregates on UTC calendar boundaries, and the front-end labels the returned
  // instants as UTC. See https://github.com/OpenCTI-Platform/opencti/issues/12150
  const SERVER_TIME_ZONES = ['UTC', 'Europe/Paris', 'America/New_York', 'Asia/Tokyo', 'Pacific/Kiritimati'];
  const initialTimeZone = process.env.TZ;

  const withTimeZone = <T>(timeZone: string, fn: () => T): T => {
    process.env.TZ = timeZone;
    return fn();
  };

  afterEach(() => {
    // Assigning undefined would store the literal string 'undefined' and leave the
    // process without a resolvable default zone for every later test.
    if (initialTimeZone === undefined) {
      delete process.env.TZ;
    } else {
      process.env.TZ = initialTimeZone;
    }
  });

  // Home dashboard "Relationships created" widget, as seen on the 26th of August 2025:
  // startDate = yearsAgo(1), endDate = lastDayOfThePreviousMonth(), interval = month.
  const monthlyKeys = ['2024-08', '2024-09', '2024-10', '2024-11', '2024-12', '2025-01', '2025-02', '2025-03', '2025-04', '2025-05', '2025-06', '2025-07'];
  const monthlyData = monthlyKeys.map((date) => ({ date, value: 10000 }));
  const monthlyStart = new Date('2024-08-26T00:00:00.000Z');
  const monthlyEnd = new Date('2025-07-31T23:59:59.999Z');

  it('should keep the last completed month on the axis', () => {
    // Under a UTC runner the buggy implementation is indistinguishable from the fixed
    // one, so this scenario has to be pinned to an offset server to stay a regression test.
    const series = withTimeZone('Europe/Paris', () => fillTimeSeries(monthlyStart, monthlyEnd, 'month', monthlyData));
    expect(series.length).toEqual(12);
    expect(series[0]).toEqual({ date: '2024-08-01T00:00:00.000Z', value: 10000 });
    expect(series[11]).toEqual({ date: '2025-07-01T00:00:00.000Z', value: 10000 });
    expect(series.every((point) => point.value === 10000)).toBe(true);
  });

  it('should emit the same monthly series whatever the server time zone', () => {
    const reference = withTimeZone('UTC', () => fillTimeSeries(monthlyStart, monthlyEnd, 'month', monthlyData));
    SERVER_TIME_ZONES.forEach((timeZone) => {
      const series = withTimeZone(timeZone, () => fillTimeSeries(monthlyStart, monthlyEnd, 'month', monthlyData));
      expect(series, `time zone ${timeZone}`).toEqual(reference);
    });
  });

  it('should align quarterly buckets on the quarter start whatever the requested start date', () => {
    // Elasticsearch keys quarter buckets on the quarter start month, so a start date
    // falling mid-quarter must be truncated: otherwise no key ever matches and the
    // chart silently flattens to zero instead of shifting.
    const quarterlyData = [
      { date: '2024-10', value: 1 },
      { date: '2025-01', value: 2 },
      { date: '2025-04', value: 3 },
      { date: '2025-07', value: 4 },
    ];
    const end = new Date('2025-09-30T23:59:59.999Z');
    const expected = [
      { date: '2024-10-01T00:00:00.000Z', value: 1 },
      { date: '2025-01-01T00:00:00.000Z', value: 2 },
      { date: '2025-04-01T00:00:00.000Z', value: 3 },
      { date: '2025-07-01T00:00:00.000Z', value: 4 },
    ];
    // Aligned on a quarter boundary, then mid-quarter, then on the last day of a quarter.
    ['2024-10-01', '2024-11-15', '2024-12-31'].forEach((day) => {
      SERVER_TIME_ZONES.forEach((timeZone) => {
        const series = withTimeZone(timeZone, () => fillTimeSeries(new Date(`${day}T00:00:00.000Z`), end, 'quarter', quarterlyData));
        expect(series, `start ${day} / time zone ${timeZone}`).toEqual(expected);
      });
    });
  });

  it('should align weekly buckets on UTC mondays whatever the server time zone', () => {
    const start = new Date('2025-07-03T00:00:00.000Z'); // thursday
    const end = new Date('2025-07-23T00:00:00.000Z'); // wednesday
    SERVER_TIME_ZONES.forEach((timeZone) => {
      const series = withTimeZone(timeZone, () => fillTimeSeries(start, end, 'week', [{ date: '2025-07-14', value: 42 }]));
      expect(series, `time zone ${timeZone}`).toEqual([
        { date: '2025-06-30T00:00:00.000Z', value: 0 },
        { date: '2025-07-07T00:00:00.000Z', value: 0 },
        { date: '2025-07-14T00:00:00.000Z', value: 42 },
        { date: '2025-07-21T00:00:00.000Z', value: 0 },
      ]);
    });
  });

  it('should emit the same daily series whatever the server time zone', () => {
    const start = new Date('2025-07-30T00:00:00.000Z');
    const end = new Date('2025-08-02T23:59:59.999Z');
    SERVER_TIME_ZONES.forEach((timeZone) => {
      const series = withTimeZone(timeZone, () => fillTimeSeries(start, end, 'day', [{ date: '2025-08-01', value: 7 }]));
      expect(series, `time zone ${timeZone}`).toEqual([
        { date: '2025-07-30T00:00:00.000Z', value: 0 },
        { date: '2025-07-31T00:00:00.000Z', value: 0 },
        { date: '2025-08-01T00:00:00.000Z', value: 7 },
        { date: '2025-08-02T00:00:00.000Z', value: 0 },
      ]);
    });
  });

  it('should emit the same hourly series whatever the server time zone', () => {
    const start = new Date('2025-07-31T22:15:00.000Z');
    const end = new Date('2025-08-01T01:00:00.000Z');
    SERVER_TIME_ZONES.forEach((timeZone) => {
      const series = withTimeZone(timeZone, () => fillTimeSeries(start, end, 'hour', [{ date: '2025-08-01 00:00:00', value: 3 }]));
      expect(series, `time zone ${timeZone}`).toEqual([
        { date: '2025-07-31T22:00:00.000Z', value: 0 },
        { date: '2025-07-31T23:00:00.000Z', value: 0 },
        { date: '2025-08-01T00:00:00.000Z', value: 3 },
        { date: '2025-08-01T01:00:00.000Z', value: 0 },
      ]);
    });
  });
});
