import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { it, expect, vi, describe, beforeEach } from 'vitest';
import { RelayEnvironmentProvider } from 'react-relay';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import { MemoryRouter } from 'react-router-dom';
import SubTypeWorkflow, { workflowQuery } from '../SubTypeWorkflow';
import { UserContext, UserContextType } from '../../../../../utils/hooks/useAuth';
import { StatusScopeEnum } from '../../../../../utils/statusConstants';
import type { SubTypeOutletContext } from '../SubTypeOutletContext';

// Mocked by each test via `mockOutletContext` below; defaults to undefined like a real
// unmatched outlet context.
let mockOutletContext: SubTypeOutletContext | undefined;

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useOutletContext: () => mockOutletContext };
});

// Bypasses the members dependencies query so tests only have to resolve workflowQuery;
// the leaf `Workflow` component (mocked below) never consumes this ref.
vi.mock('../../../../../utils/hooks/useQueryLoading', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../../utils/hooks/useQueryLoading')>();
  return { ...actual, default: () => ({}) };
});

// `Workflow.tsx` rendering itself is already covered by Workflow.test.tsx; here we only
// need to assert what SubTypeWorkflow passes down as props.
vi.mock('../workflow/Workflow', () => ({
  default: ({ canSwitchScope, scope, onScopeChange }: {
    canSwitchScope?: boolean;
    scope?: StatusScopeEnum;
    onScopeChange?: (scope: StatusScopeEnum) => void;
  }) => (
    <div data-testid="workflow-mock">
      {canSwitchScope && (
        <div>
          <button onClick={() => onScopeChange?.(StatusScopeEnum.GLOBAL)}>
            {scope === StatusScopeEnum.GLOBAL ? 'Global (selected)' : 'Global'}
          </button>
          <button onClick={() => onScopeChange?.(StatusScopeEnum.REQUEST_ACCESS)}>
            {scope === StatusScopeEnum.REQUEST_ACCESS ? 'Request Access (selected)' : 'Request Access'}
          </button>
        </div>
      )}
    </div>
  ),
}));

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

describe('scope switcher wiring', () => {
  const requestAccessEnabledSubType = {
    settings: {
      availableSettings: ['request_access_workflow'],
      requestAccessConfiguration: {},
    },
  } as unknown as SubTypeOutletContext['subType'];

  const requestAccessDisabledSubType = {
    settings: {
      availableSettings: [],
      requestAccessConfiguration: null,
    },
  } as unknown as SubTypeOutletContext['subType'];

  const eeUserContext = {
    settings: { platform_enterprise_edition: { license_validated: true } },
  } as unknown as UserContextType;

  beforeEach(() => {
    mockOutletContext = undefined;
  });

  const renderSubTypeWorkflow = (subType: SubTypeOutletContext['subType']) => {
    const environment = createMockEnvironment();
    mockOutletContext = { subType, tabs: {} as SubTypeOutletContext['tabs'] };

    render(
      <MemoryRouter>
        <RelayEnvironmentProvider environment={environment}>
          <UserContext.Provider value={eeUserContext}>
            <SubTypeWorkflow entityType="Incident" />
          </UserContext.Provider>
        </RelayEnvironmentProvider>
      </MemoryRouter>,
    );

    environment.mock.resolveMostRecentOperation((op) => MockPayloadGenerator.generate(op));

    return environment;
  };

  it('renders the Global/Request Access switcher when RequestAccess config is available and EE is enabled', async () => {
    renderSubTypeWorkflow(requestAccessEnabledSubType);

    expect(await screen.findByText('Global (selected)')).toBeInTheDocument();
    expect(screen.getByText('Request Access')).toBeInTheDocument();
  });

  it('re-fires workflowDefinition with scope=REQUEST_ACCESS when Request Access is selected', async () => {
    const user = userEvent.setup();
    const environment = renderSubTypeWorkflow(requestAccessEnabledSubType);

    const requestAccessButton = await screen.findByText('Request Access');
    await user.click(requestAccessButton);

    await waitFor(() => {
      const operation = environment.mock.getMostRecentOperation();
      expect(operation.request.node.params.name).toBe(workflowQuery.params.name);
      expect(operation.request.variables.scope).toBe(StatusScopeEnum.REQUEST_ACCESS);
    });
  });

  it('does not render the switcher when the subType has no RequestAccess config', async () => {
    renderSubTypeWorkflow(requestAccessDisabledSubType);

    await screen.findByTestId('workflow-mock');
    expect(screen.queryByText('Global')).not.toBeInTheDocument();
    expect(screen.queryByText('Request Access')).not.toBeInTheDocument();
  });
});
