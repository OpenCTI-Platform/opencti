import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../../tests/test-render';
import * as env from '../../../../relay/environment';
import useDonutOutcome from './useDonutOutcome';

vi.mock('../apexchartUtils', () => ({
  default: vi.fn(async () => 'data:image/png;base64,abc'),
}));

vi.mock('../../../hooks/useDistributionGraphData', () => ({
  default: () => ({
    buildWidgetLabelsOption: () => ['Zero bucket'],
  }),
}));

describe('Hook: useDonutOutcome', () => {
  beforeAll(() => {
    vi.spyOn(env, 'fetchQuery');
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should expose empty metadata for an empty donut dataset even when html output is an image', async () => {
    const { hook, relayEnv } = testRenderHook(() => useDonutOutcome());
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildDonutOutcome } = hook.result.current;

    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        Query() {
          return {
            stixRelationshipsDistribution: [{
              label: 'Zero bucket',
              value: 0,
              entity: {
                color: '#000000',
              },
            }],
          };
        },
      });
    });

    const outcome = await buildDonutOutcome({}, { includeMetadata: true });

    expect(outcome.isEmpty).toEqual(true);
    expect(outcome.html).toContain('<img src="data:image/png;base64,abc"');
  });
});
