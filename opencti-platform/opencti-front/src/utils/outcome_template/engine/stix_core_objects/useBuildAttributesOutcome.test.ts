import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../../tests/test-render';
import * as env from '../../../../relay/environment';
import useBuildAttributesOutcome from './useBuildAttributesOutcome';
import * as filterUtils from '../../../filters/filtersUtils';
import { SELF_ID } from '../../../filters/filtersUtils';

describe('Hook: useBuildAttributesOutcome', () => {
  beforeAll(() => {
    vi.spyOn(filterUtils, 'useBuildFilterKeysMapFromEntityType').mockImplementation(() => new Map());
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should throw an error if no instance ID is given', () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildAttributesOutcome());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a));
    const { buildAttributesOutcome } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op);
    });

    const call = () => buildAttributesOutcome('id_XX', { columns: [] });
    expect(call).rejects.toThrowError('The attribute widget should refers to an instance');
  });

  it('should return resolved variables of the widget', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildAttributesOutcome());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a));
    const { buildAttributesOutcome } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        String(ctx) {
          if (ctx.name === 'name') return 'Super Report';
          return 'testing-data';
        },
        Label() {
          return { value: 'a-label' };
        },
        MarkingDefinition() {
          return { definition: 'tlp:red' };
        },
      });
    });

    const attributesOutcome = await buildAttributesOutcome(
      'id_XX',
      {
        instance_id: SELF_ID,
        columns: [
          { variableName: 'reportName', attribute: 'name', label: 'Name' },
          { variableName: 'reportLabels', attribute: 'objectLabel.value' },
          { variableName: 'reportMarkings', attribute: 'objectMarking.definition', displayStyle: 'list' },
        ],
      },
    );

    const name = attributesOutcome.find((o) => o.variableName === 'reportName')?.attributeData;
    const labels = attributesOutcome.find((o) => o.variableName === 'reportLabels')?.attributeData;
    const markings = attributesOutcome.find((o) => o.variableName === 'reportMarkings')?.attributeData;
    expect(name).toEqual('Super Report');
    expect(labels).toEqual('a-label');
    expect(markings).toEqual('<ul><li>tlp:red</li></ul>');
  });
});
