import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { MockPayloadGenerator } from 'relay-test-utils';
import { fetchQuery } from 'react-relay';
import { createMockUserContext, testRenderHook } from '../../../tests/test-render';
import useBuildListOutcome, { resolvePlatformBaseUrl } from './useBuildListOutcome';
import * as env from '../../../../relay/environment';
import { APP_BASE_PATH } from '../../../../relay/environment';
import * as filterUtils from '../../../filters/filtersUtils';

/**
 * Utils function to generate fake data for our test.
 */
const edgeSCO = (id: string, entity_type: string, main: string, created_at: string) => ({
  node: {
    id,
    entity_type,
    created_at,
    representative: {
      main,
    },
  },
});

// Every value slot must be set, otherwise the mock generator fills it with a placeholder.
const emptyCustomFieldValue = {
  int_value: null,
  string_value: null,
  boolean_value: null,
  date_value: null,
  select_value: null,
  select_values: null,
};

describe('Hook: useBuildListOutcome', () => {
  beforeAll(() => {
    vi.spyOn(filterUtils, 'useBuildFilterKeysMapFromEntityType').mockImplementation(() => {
      return new Map().set('created_at', { type: 'date' });
    });
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should have a table containing data from query', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildListOutcome());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildListOutcome } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        StixCoreObjectConnection() {
          return {
            edges: [
              edgeSCO('sco1', 'Malware', 'Vador', '2024-05-21T08:20:59.859Z'),
              edgeSCO('sco2', 'Malware', 'Joker', '2024-05-25T08:20:34.859Z'),
              edgeSCO('sco3', 'Location', 'Annecy', '2023-05-25T08:20:34.859Z'),
            ],
          };
        },
      });
    });

    const listOutcome = await buildListOutcome({}, 'entities');

    expect(listOutcome).toContain('<tr><td>Malware</td><td>Vador</td><td>2024-05-21</td></tr>');
    expect(listOutcome).toContain('<tr><td>Malware</td><td>Joker</td><td>2024-05-25</td></tr>');
    expect(listOutcome).toContain('<tr><td>Location</td><td>Annecy</td><td>2023-05-25</td></tr>');
  });

  it('should format object-based columns as readable values', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildListOutcome());
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildListOutcome } = hook.result.current;

    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        StixCoreObjectConnection() {
          return {
            edges: [{
              node: {
                id: 'sco-object-columns',
                entity_type: 'Report',
                createdBy: { id: 'identity-1', name: 'Alice' },
                creators: [{ id: 'creator-1', name: 'Bob' }, { id: 'creator-2', name: 'Carol' }],
                objectLabel: [{ id: 'label-1', value: 'TLP:AMBER' }],
                objectMarking: [{ id: 'marking-1', definition: 'TLP:CLEAR' }],
                status: { id: 'status-1', template: { name: 'In progress' } },
              },
            }],
          };
        },
      });
    });

    const listOutcome = await buildListOutcome({
      columns: [
        { attribute: 'createdBy', label: 'Author' },
        { attribute: 'creators', label: 'Creators' },
        { attribute: 'objectLabel', label: 'Label' },
        { attribute: 'objectMarking', label: 'Marking definition' },
        { attribute: 'x_opencti_workflow_id', label: 'Processing status' },
      ],
    }, 'entities');
    const normalizedOutcome = listOutcome.replaceAll('\u200B', '');

    expect(normalizedOutcome).toContain('<td>Alice</td>');
    expect(normalizedOutcome).toContain('<td>Bob, Carol</td>');
    expect(normalizedOutcome).toContain('<td>TLP:AMBER</td>');
    expect(normalizedOutcome).toContain('<td>TLP:CLEAR</td>');
    expect(normalizedOutcome).toContain('<td>In progress</td>');
  });

  it('should read custom field columns from the custom field values', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildListOutcome());
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildListOutcome } = hook.result.current;

    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        StixCoreObjectConnection() {
          return {
            edges: [{
              node: {
                id: 'area-1',
                entity_type: 'Administrative-Area',
                representative: { main: 'Demo zone' },
                customFieldValues: [
                  { ...emptyCustomFieldValue, field_id: 'cf-1', field_name: 'x_opencti_cf_level', select_value: 'secret' },
                  { ...emptyCustomFieldValue, field_id: 'cf-2', field_name: 'x_opencti_cf_tags', select_values: ['a', 'b'] },
                ],
              },
            }],
          };
        },
      });
    });

    const listOutcome = await buildListOutcome({
      columns: [
        { attribute: 'representative.main', label: 'Name' },
        { attribute: 'x_opencti_cf_level', label: 'Confidentiality' },
        { attribute: 'x_opencti_cf_tags', label: 'Tags' },
        { attribute: 'x_opencti_cf_missing', label: 'Missing' },
      ],
    }, 'entities');

    expect(listOutcome).toContain('<td>Demo zone</td><td>secret</td>');
    expect(listOutcome).toContain('<td>a, b</td>');
  });

  it('should read custom field columns from the custom field values of relationships and sightings', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildListOutcome());
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildListOutcome } = hook.result.current;

    const relationshipNode = (__typename: string, id: string, note: string) => ({
      __typename,
      id,
      entity_type: __typename === 'StixSightingRelationship' ? 'stix-sighting-relationship' : 'targets',
      customFieldValues: [{ ...emptyCustomFieldValue, field_id: 'cf-note', field_name: 'x_opencti_cf_note', string_value: note }],
    });
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        StixRelationshipConnection() {
          return {
            edges: [
              { node: relationshipNode('StixCoreRelationship', 'rel-1', 'first') },
              { node: relationshipNode('StixSightingRelationship', 'sighting-1', 'second') },
            ],
          };
        },
      });
    });

    const listOutcome = await buildListOutcome({ columns: [{ attribute: 'x_opencti_cf_note', label: 'Note' }] }, 'relationships');

    expect(listOutcome).toContain('<tr><td>first</td></tr><tr><td>second</td></tr>');
  });

  it('should render the entity link column as a link to the entity page', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildListOutcome(), {
      userContext: createMockUserContext({ settings: { platform_url: 'https://opencti.example.com/' } }),
    });
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildListOutcome } = hook.result.current;

    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        StixCoreObjectConnection() {
          return {
            edges: [edgeSCO('sco1', 'Malware', 'Vador', '2024-05-21T08:20:59.859Z')],
          };
        },
      });
    });

    const listOutcome = await buildListOutcome({
      columns: [
        { attribute: 'representative.main', label: 'Name' },
        { attribute: 'entity_link', label: 'OpenCTI entity link' },
      ],
    }, 'entities');

    expect(listOutcome).toContain('<th>OpenCTI entity link</th>');
    expect(listOutcome).toContain('<tr><td>Vador</td><td><a href="https://opencti.example.com/dashboard/id/sco1">View in OpenCTI</a></td></tr>');
  });

  it('should expose empty metadata when the list has headers but no rows', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildListOutcome());
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildListOutcome } = hook.result.current;

    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        StixCoreObjectConnection() {
          return {
            edges: [],
          };
        },
      });
    });

    const listOutcome = await buildListOutcome({}, 'entities', { includeMetadata: true });

    expect(listOutcome.isEmpty).toEqual(true);
    expect(listOutcome.html).toContain('<thead>');
    expect(listOutcome.html).toContain('<tbody></tbody>');
  });
});

describe('Function: resolvePlatformBaseUrl', () => {
  it('should use the configured platform URL without trailing slash', () => {
    expect(resolvePlatformBaseUrl('https://opencti.example.com/base/')).toEqual('https://opencti.example.com/base');
  });

  it('should fall back on the current location if the platform URL is missing or relative', () => {
    expect(resolvePlatformBaseUrl(undefined)).toEqual(`${window.location.origin}${APP_BASE_PATH}`);
    expect(resolvePlatformBaseUrl('')).toEqual(`${window.location.origin}${APP_BASE_PATH}`);
    expect(resolvePlatformBaseUrl('/base')).toEqual(`${window.location.origin}${APP_BASE_PATH}`);
  });
});
