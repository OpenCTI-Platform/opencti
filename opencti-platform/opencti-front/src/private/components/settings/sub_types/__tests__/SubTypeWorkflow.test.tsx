import { render } from '@testing-library/react';
import { it, expect } from 'vitest';
import { RelayEnvironmentProvider } from 'react-relay';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import { MemoryRouter } from 'react-router-dom';
import SubTypeWorkflow, { workflowQuery } from '../SubTypeWorkflow';

it('queries workflowDefinition with the provided entityType, not a hardcoded literal', () => {
  const environment = createMockEnvironment();

  render(
    <MemoryRouter>
      <RelayEnvironmentProvider environment={environment}>
        <SubTypeWorkflow entityType="Incident" />
      </RelayEnvironmentProvider>
    </MemoryRouter>,
  );

  const operation = environment.mock.getMostRecentOperation();

  expect(operation.request.node.params.name).toBe(workflowQuery.params.name);
  expect(operation.request.variables.entityType).toBe('Incident');

  environment.mock.resolveMostRecentOperation((op) => MockPayloadGenerator.generate(op));
});
