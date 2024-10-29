import { describe, expect, it, vi } from 'vitest';
import { MockPayloadGenerator } from 'relay-test-utils';
import { fetchQuery } from 'react-relay';
import { testRenderHook } from '../../../tests/test-render';
import * as env from '../../../../relay/environment';
import useBuildAttributesOutcome from './useBuildAttributesOutcome';
import type { TemplateWidget } from '../../template';

describe('Hook: useBuildAttributesOutcome', () => {
  it('should have variables from query', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildAttributesOutcome());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a));
    const { buildAttributesOutcome } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        StixCoreObject() {
          return {
            representative: { main: 'report1', secondary: 'report1 description' },
            entity_type: 'Report',
            objectLabel: [
              { value: 'label1', color: 'red' },
              { value: 'label2', color: 'blue' },
            ],
            objectMarking: [
              { definition_type: 'TLP', definition: 'TLP:marking1' },
              { definition_type: 'TLP', definition: 'TLP:marking2' },
            ],
          };
        },
      });
    });

    const templateWidget = {
      name: 'attributeTemplateWidgetForTest',
      widget: {
        type: 'attribute',
        id: 'XXX',
        perspective: 'entities',
        dataSelection: [
          {
            columns: [
              { variableName: 'reportName', attribute: 'name', label: 'Name' },
              { variableName: 'reportLabels', attribute: 'objectLabel.value' },
              { variableName: 'reportMarkings', attribute: 'objectMarking.definition', displayStyle: 'list' },
            ],
            instance_id: 'CONTAINER_ID',
          },
        ],
      },
    } as TemplateWidget;
    const attributesOutcome = await buildAttributesOutcome('id_XX', templateWidget);

    expect(attributesOutcome.filter((o) => o.variableName === 'reportName')[0].attributeData)
      .toEqual('<mock-value-for-field-"name">');
    expect(attributesOutcome.filter((o) => o.variableName === 'reportLabels')[0].attributeData)
      .toEqual('<mock-value-for-field-"value">');
  });
});
