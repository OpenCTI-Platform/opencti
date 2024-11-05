import { describe, it, expect, vi } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../tests/test-render';
import useContentFromTemplate from './useContentFromTemplate';
import * as env from '../../../relay/environment';
import * as useBuildAttributesOutcome from './stix_core_objects/useBuildAttributesOutcome';
import * as useBuildListOutcome from './stix_core_objects/useBuildListOutcome';

describe('Hook: useContentFromTemplate', () => {
  it('should replace attribute widgets with the associated data', async () => {
    vi.spyOn(useBuildAttributesOutcome, 'default').mockImplementation(() => ({
      buildAttributesOutcome: async () => {
        return [
          { variableName: 'containerName', attributeData: 'Super report' },
          { variableName: 'containerType', attributeData: 'Report' },
        ];
      },
    }));

    const { hook, relayEnv } = testRenderHook(() => useContentFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a));
    const { buildContentFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        Template() {
          return {
            id: 'testTemplate',
            name: 'Test template',
            used_widgets: ['containerName', 'containerType'],
            content: 'Hello, I am container $containerName of type $containerType',
          };
        },
        TemplateWidget() {
          return {
            widget: {
              type: 'attribute',
              dataSelection: [{}],
            },
          };
        },
      });
    });

    const content = await buildContentFromTemplate('aaaID', 'testTemplate', []);
    expect(content).toEqual('Hello, I am container Super report of type Report');
  });

  it('should replace attribute lists with corresponding data', async () => {
    vi.spyOn(useBuildListOutcome, 'default').mockImplementation(() => ({
      buildListOutcome: async () => {
        return 'my super list of elements';
      },
    }));

    const { hook, relayEnv } = testRenderHook(() => useContentFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a));
    const { buildContentFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        Template() {
          return {
            id: 'testTemplate',
            name: 'Test template',
            used_widgets: ['containerList'],
            content: 'Hello, I have: $containerList',
          };
        },
        TemplateWidget() {
          return {
            name: 'containerList',
            widget: {
              type: 'list',
              dataSelection: [{
                filters: null,
              }],
            },
          };
        },
      });
    });

    const content = await buildContentFromTemplate('aaaID', 'testTemplate', []);
    expect(content).toEqual('Hello, I have: my super list of elements');
  });
});
