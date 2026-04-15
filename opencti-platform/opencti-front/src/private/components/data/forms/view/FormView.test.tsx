import { describe, it, vi, expect, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import FormView from './FormView';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { MockPayloadGenerator } from 'relay-test-utils';
import * as useGrantedModule from '../../../../../utils/hooks/useGranted';

vi.mock('../../../common/form/AuthorizedMembersField', () => ({
  __esModule: true,
  default: (props: { disabled?: boolean }) => (
    <div data-testid="authorized-members-disabled">{String(!!props.disabled)}</div>
  ),
}));

vi.mock('../../../common/form/CreatedByField', () => ({
  __esModule: true,
  default: (props: { name?: string; label?: string; helpertext?: string }) => (
    <div data-testid="created-by-field">
      <label>{props.label}</label>
      {props.helpertext && <span data-testid="created-by-helpertext">{props.helpertext}</span>}
    </div>
  ),
}));

vi.mock('../../../common/form/ObjectAssigneeField', () => ({
  __esModule: true,
  default: (props: { name?: string }) => <div data-testid={`assignee-field-${props.name}`} />,
}));

vi.mock('../../../common/form/ObjectParticipantField', () => ({
  __esModule: true,
  default: (props: { name?: string }) => <div data-testid={`participant-field-${props.name}`} />,
}));

// Mock useParams
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useParams: () => ({ formId: 'form-id' }),
    useNavigate: () => vi.fn(),
  };
});

// Mock useGranted
const useGrantedSpy = vi.spyOn(useGrantedModule, 'default');

const makeMockForm = (draftDefaults: object) => ({
  id: 'form-id',
  name: 'Test Form',
  description: 'Test Description',
  active: true,
  form_schema: JSON.stringify({
    fields: [
      { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
    ],
    mainEntityType: 'Report',
    isDraftByDefault: true,
    draftDefaults,
  }),
});

const defaultMockForm = makeMockForm({
  author: { type: 'none', isEditable: false },
  authorizedMembers: { enabled: true, defaults: [] },
});

// entitySettings: { edges: [] } is required to match what FormView expects from the user context
const mockUserContext = createMockUserContext({ entitySettings: { edges: [] } });

const resolveAndWait = async (relayEnv: ReturnType<typeof testRender>['relayEnv'], form: object) => {
  await waitFor(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) =>
      MockPayloadGenerator.generate(operation, { Form: () => form }),
    );
  });
  await waitFor(() => {
    expect(screen.getAllByText('Test Form').length).toBeGreaterThan(0);
  });
};

describe('FormView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render form and fields', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, defaultMockForm);
  });

  it('should render AuthorizedMembers disabled when user lacks BYPASS', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      return true;
    });
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, defaultMockForm);
    expect(screen.getByTestId('authorized-members-disabled')).toHaveTextContent('true');
  });

  it('should render AuthorizedMembers enabled when user has BYPASS', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, defaultMockForm);
    expect(screen.getByTestId('authorized-members-disabled')).toHaveTextContent('false');
  });

  it('should render draftName field when enabled and editable', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      name: { enabled: true, isEditable: true, isRequired: false, defaultValue: 'Default Draft' },
    }));
    expect(screen.getByLabelText(/Draft name/i)).toBeTruthy();
  });

  it('should NOT render draftName field when not enabled', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      name: { enabled: false, isEditable: false, isRequired: false },
    }));
    expect(screen.queryByLabelText(/Draft name/i)).toBeNull();
  });

  it('should NOT render draftName for non-bypass when isEditable=false', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      return true;
    });
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      name: { enabled: true, isEditable: false, isRequired: false, defaultValue: 'Draft' },
    }));
    expect(screen.queryByLabelText(/Draft name/i)).toBeNull();
  });

  it('should render draftName for bypass user even when isEditable=false', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      name: { enabled: true, isEditable: false, isRequired: false, defaultValue: 'Draft' },
    }));
    expect(screen.getByLabelText(/Draft name/i)).toBeTruthy();
  });

  it('should render draftDescription field when enabled and editable', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      description: { enabled: true, isEditable: true, isRequired: false, defaultValue: 'Desc' },
    }));
    // MarkdownField uses a visual label (not linked via 'for'), so use text query
    expect(screen.getByText(/Draft description/i)).toBeTruthy();
  });

  it('should NOT render draftDescription when not enabled', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      description: { enabled: false, isEditable: true, isRequired: false },
    }));
    expect(screen.queryByText(/Draft description/i)).toBeNull();
  });

  it('should render ObjectAssigneeField when enabled and editable', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      objectAssignee: { enabled: true, isEditable: true, isRequired: false, defaults: [] },
    }));
    expect(screen.getByTestId('assignee-field-draftObjectAssignee')).toBeTruthy();
  });

  it('should NOT render ObjectAssigneeField when not enabled', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      objectAssignee: { enabled: false, isEditable: true, isRequired: false, defaults: [] },
    }));
    expect(screen.queryByTestId('assignee-field-draftObjectAssignee')).toBeNull();
  });

  it('should render ObjectParticipantField when enabled and editable', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      objectParticipant: { enabled: true, isEditable: true, isRequired: false, defaults: [] },
    }));
    expect(screen.getByTestId('participant-field-draftObjectParticipant')).toBeTruthy();
  });

  it('should render CreatedByField with helper text for main_entity_author type', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      author: { type: 'main_entity_author', isEditable: true, isRequired: false },
    }));
    expect(screen.getByTestId('created-by-field')).toBeTruthy();
    expect(screen.getByTestId('created-by-helpertext')).toBeTruthy();
  });

  it('should render CreatedByField without helpertext for static type', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      author: { type: 'static', isEditable: true, isRequired: false, defaultValue: 'identity-1', defaultValueLabel: 'Org A' },
    }));
    expect(screen.getByTestId('created-by-field')).toBeTruthy();
    expect(screen.queryByTestId('created-by-helpertext')).toBeNull();
  });

  it('should NOT render CreatedByField when isEditable=false and user lacks BYPASS', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      return true;
    });
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      author: { type: 'static', isEditable: false, isRequired: false, defaultValue: 'identity-1' },
    }));
    expect(screen.queryByTestId('created-by-field')).toBeNull();
  });
});
