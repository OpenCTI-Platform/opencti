import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../tests/test-render';
import useFileFromTemplate from './useFileFromTemplate';
import * as env from '../../../relay/environment';
import * as useBuildAttributesOutcome from './stix_core_objects/useBuildAttributesOutcome';
import * as useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import * as filterUtils from '../../filters/filtersUtils';

describe('Hook: useFileFromTemplate', () => {
  const buildAttributesOutcomeMock = vi.fn(async () => {
    return [
      { variableName: 'containerName', attributeData: 'Super report' },
      { variableName: 'containerType', attributeData: 'Report' },
    ];
  });
  beforeAll(() => {
    vi.spyOn(useBuildAttributesOutcome, 'default').mockImplementation(() => ({
      buildAttributesOutcome: buildAttributesOutcomeMock,
    }));
    vi.spyOn(useBuildListOutcome, 'default').mockImplementation(() => ({
      buildListOutcome: async () => {
        return 'my super list of elements';
      },
    }));
    vi.spyOn(filterUtils, 'useBuildFiltersForTemplateWidgets').mockImplementation(() => ({
      buildFiltersForTemplateWidgets() {
        return undefined;
      },
      buildNotAllowedMarkingIds(maxContentMarkingsIds: string[]) {
        return maxContentMarkingsIds.includes('tlp-amber') ? ['tlp-red'] : ['tlp-amber', 'tlp-red'];
      },
    }));
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should replace attribute widgets with the associated data', async () => {
    const { hook, relayEnv } = testRenderHook(() => useFileFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildFileFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        FintelTemplate() {
          return {
            id: 'testTemplate',
            name: 'Test template',
            fintel_template_widgets: [{
              id: 'XXXX',
              variable_name: 'myAttributes',
              widget: {
                type: 'attribute',
                dataSelection: [{}],
              },
            }],
            template_content: 'Hello, I am container $containerName of type $containerType',
          };
        },
      });
    });

    const content = await buildFileFromTemplate('aaaID', ['tlp-amber'], 'testTemplate');
    expect(content).toEqual('Hello, I am container Super report of type Report');
    // the attribute widget receives the markings above the limits of the export
    expect(buildAttributesOutcomeMock).toHaveBeenLastCalledWith('aaaID', expect.anything(), ['tlp-red']);
  });

  it('should replace attribute lists with corresponding data', async () => {
    const { hook, relayEnv } = testRenderHook(() => useFileFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildFileFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        FintelTemplate() {
          return {
            id: 'testTemplate',
            name: 'Test template',
            fintel_template_widgets: [{
              id: 'YYY',
              variable_name: 'containerList',
              widget: {
                type: 'list',
                dataSelection: [{
                  filters: null,
                }],
              },
            }],
            template_content: 'Hello, I have: $containerList',
          };
        },
      });
    });

    const content = await buildFileFromTemplate('aaaID', [], 'testTemplate');
    expect(content).toEqual('Hello, I have: my super list of elements');
  });
});
