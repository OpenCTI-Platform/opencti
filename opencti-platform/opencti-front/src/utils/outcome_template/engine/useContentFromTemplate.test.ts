import { describe, it, expect, vi } from 'vitest';
import { fetchQuery } from 'react-relay';
import type { GraphQLTaggedNode, Variables } from 'relay-runtime';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../tests/test-render';
import useContentFromTemplate from './useContentFromTemplate';
import * as env from '../../../relay/environment';
import type { Widget } from '../../widget/widget';

describe('Hook: useContentFromTemplate', () => {
  it('should replace attribute widgets with the associated data', async () => {
    const { hook } = testRenderHook(() => useContentFromTemplate());
    const { buildContentFromTemplate } = hook.result.current;

    const template = {
      name: 'Test template',
      used_widgets: ['containerName', 'containerType'],
      content: 'Hello, I am container $containerName of type $containerType',
    };
    const attributes = [
      { template_widget_name: 'containerName', data: 'Super report' },
      { template_widget_name: 'containerType', data: 'Report' },
    ];

    const content = await buildContentFromTemplate('aaaID', template, [], attributes, []);
    expect(content).toEqual('Hello, I am container Super report of type Report');
  });

  it('should replace attribute lists with corresponding data fetched', async () => {
    const { hook, relayEnv } = testRenderHook(() => useContentFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q: GraphQLTaggedNode, a: Variables) => fetchQuery(relayEnv, q, a));
    const { buildContentFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        StixCoreObjectConnection() {
          return {
            edges: [
              {
                node: {
                  id: 'malware1',
                  entity_type: 'Malware',
                  created_at: '2022-07-12T08:20:59.859Z',
                  representative: {
                    main: 'PasGentil',
                  },
                },
              },
            ],
          };
        },
      });
    });

    const template = {
      name: 'Test template',
      used_widgets: ['containerName', 'containerEntities'],
      content: 'Hello, I am container $containerName my entities are $containerEntities',
    };
    const attributes = [{
      template_widget_name: 'containerName',
      data: 'MyReport',
    }];
    const widgets = [{
      name: 'containerEntities',
      widget: { dataSelection: [{}], type: 'list' } as unknown as Widget,
    }];

    const content = await buildContentFromTemplate('aaaID', template, widgets, attributes, []);
    expect(content).toEqual('Hello, I am container MyReport my entities are <table><thead><tr><th>Entity type</th><th>Representative</th><th>Creation date</th></tr></thead><tbody><tr><td>Malware</td><td>PasGentil</td><td>2022-07-12T08:20:59.859Z</td></tr></tbody></table>');
  });
});
