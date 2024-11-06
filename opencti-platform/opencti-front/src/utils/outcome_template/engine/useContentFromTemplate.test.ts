import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../tests/test-render';
import useContentFromTemplate from './useContentFromTemplate';
import * as env from '../../../relay/environment';
import * as useBuildAttributesOutcome from './stix_core_objects/useBuildAttributesOutcome';
import * as useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import * as filterUtils from '../../filters/filtersUtils';

describe('Hook: useContentFromTemplate', () => {
  beforeAll(() => {
    vi.spyOn(useBuildAttributesOutcome, 'default').mockImplementation(() => ({
      buildAttributesOutcome: async () => {
        return [
          { variableName: 'containerName', attributeData: 'Super report' },
          { variableName: 'containerType', attributeData: 'Report' },
        ];
      },
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
    }));
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should replace attribute widgets with the associated data', async () => {
    const { hook, relayEnv } = testRenderHook(() => useContentFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a));
    const { buildContentFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        TemplateAndUtils() {
          return {
            template: {
              id: 'testTemplate',
              name: 'Test template',
              template_widgets_ids: ['myAttributes'],
              content: 'Hello, I am container $containerName of type $containerType',
            },
            template_widgets: [{
              id: 'myAttributes',
              type: 'attribute',
              dataSelection: [{}],
            }],
          };
        },
      });
    });

    const content = await buildContentFromTemplate('aaaID', 'testTemplate', []);
    expect(content).toEqual('Hello, I am container Super report of type Report');
  });

  it('should replace attribute lists with corresponding data', async () => {
    const { hook, relayEnv } = testRenderHook(() => useContentFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a));
    const { buildContentFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        TemplateAndUtils() {
          return {
            template: {
              id: 'testTemplate',
              name: 'Test template',
              template_widgets_ids: ['containerList'],
              content: 'Hello, I have: $containerList',
            },
            template_widgets: [{
              id: 'containerList',
              type: 'list',
              dataSelection: [{
                filters: null,
              }],
            }],
          };
        },
      });
    });

    const content = await buildContentFromTemplate('aaaID', 'testTemplate', []);
    expect(content).toEqual('Hello, I have: my super list of elements');
  });
});
