import React from 'react';
import { waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import DefenseProvidedDataComponents from './DefenseProvidedDataComponents';

describe('Defense provided telemetry', () => {
  it('should list only the telemetry declarations that are not revoked', async () => {
    const { relayEnv } = testRender(<DefenseProvidedDataComponents entityId="platform-1" />);
    const providedQuery = () => relayEnv.mock.getAllOperations().find((operation) => operation.request.node.params.name === 'DefenseProvidedDataComponentsQuery');
    await waitFor(() => expect(providedQuery()).toBeDefined());
    expect(providedQuery()?.request.variables).toMatchObject({
      fromId: ['platform-1'],
      filters: { mode: 'and', filters: [{ key: ['revoked'], values: ['false'] }], filterGroups: [] },
    });
  });
});
