import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { MockPayloadGenerator } from 'relay-test-utils';
import { fetchQuery } from 'react-relay';
import { testRenderHook } from '../../../tests/test-render';
import useBuildListOutcome from './useBuildListOutcome';
import * as env from '../../../../relay/environment';
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
});
