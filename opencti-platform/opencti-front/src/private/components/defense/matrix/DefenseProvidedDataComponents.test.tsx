import React from 'react';
import { act, screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import type { RelayMockEnvironment } from 'relay-test-utils/lib/RelayModernMockEnvironment';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import DefenseProvidedDataComponents from './DefenseProvidedDataComponents';

const providedQuery = (relayEnv: RelayMockEnvironment) => relayEnv.mock.getAllOperations()
  .find((operation) => operation.request.node.params.name === 'DefenseProvidedDataComponentsQuery');

const declaration = (id: string, name: string, revoked: boolean) => ({
  node: { id: `provides-${id}`, description: null, to: { __typename: 'DataComponent', id, name, entity_type: 'Data-Component', revoked } },
});

describe('Defense provided telemetry', () => {
  it('should list only the telemetry declarations that are not revoked', async () => {
    const { relayEnv } = testRender(<DefenseProvidedDataComponents entityId="platform-1" />);
    await waitFor(() => expect(providedQuery(relayEnv)).toBeDefined());
    expect(providedQuery(relayEnv)?.request.variables).toMatchObject({
      fromId: ['platform-1'],
      filters: { mode: 'and', filters: [{ key: ['revoked'], values: ['false'] }], filterGroups: [] },
    });
  });

  it('should leave out the declarations of a revoked data component, as the levels do', async () => {
    const { relayEnv } = testRender(<DefenseProvidedDataComponents entityId="platform-1" />);
    await waitFor(() => expect(providedQuery(relayEnv)).toBeDefined());
    const operation = providedQuery(relayEnv)!;
    await act(async () => {
      // Resolved by query: the operation holds the default cursor, which the request does not send
      relayEnv.mock.resolve(operation.request.node, MockPayloadGenerator.generate(operation, {
        StixCoreRelationshipConnection: () => ({
          edges: [declaration('data-component-1', 'Process Creation', false), declaration('data-component-2', 'Revoked component', true)],
          pageInfo: { endCursor: null, hasNextPage: false },
        }),
      }));
    });
    expect(await screen.findByText('Process Creation')).toBeInTheDocument();
    expect(screen.queryByText('Revoked component')).not.toBeInTheDocument();
  });
});
