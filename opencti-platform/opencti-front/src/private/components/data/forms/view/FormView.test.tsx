import { screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as useGrantedModule from '../../../../../utils/hooks/useGranted';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { useDeferredCreation } from '../../../../../utils/hooks/useDeferredCreation';
import FormView from './FormView';

vi.mock('../../../common/form/AuthorizedMembersField', () => ({
  __esModule: true,
  default: () => (
    <div data-testid="authorized-members-field" />
  ),
}));

vi.mock('../../../common/form/CreatedByField', () => ({
  __esModule: true,
  default: (props: { name?: string; label?: string }) => (
    <div data-testid="created-by-field" data-deferred={String(useDeferredCreation().isDeferredMode)}>
      <label>{props.label}</label>
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

// The lookups: shows whether on-the-fly creation is offered, and can pick an object created on the fly
vi.mock('../../../common/form/StixCoreObjectsField', async () => {
  const { useField } = await vi.importActual<typeof import('formik')>('formik');
  return {
    __esModule: true,
    default: ({ name, disableCreation }: { name: string; disableCreation?: boolean }) => {
      const [, , { setValue }] = useField(name);
      return (
        <div data-testid={`lookup-${name}`} data-disable-creation={String(!!disableCreation)}>
          <button type="button" onClick={() => setValue([{ value: 'pending-1', label: 'On the fly', isPendingCreation: true }])}>
            {`pick on the fly ${name}`}
          </button>
        </div>
      );
    },
  };
});

const mockNavigate = vi.hoisted(() => vi.fn());

// Mock useParams
vi.mock('react-router', async () => {
  const actual = await vi.importActual('react-router');
  return {
    ...actual,
    useParams: () => ({ formId: 'form-id' }),
    useNavigate: () => mockNavigate,
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
const mockUserContext = createMockUserContext({
  entitySettings: { edges: [] },
});

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

  it('should NOT render AuthorizedMembers when user lacks BYPASS and field is not editable', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      if (capabilities.includes(useGrantedModule.KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS)) return false;
      return true;
    });
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, defaultMockForm);
    expect(screen.queryByTestId('authorized-members-field')).toBeNull();
  });

  it('should render AuthorizedMembers when user has BYPASS', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, defaultMockForm);
    expect(screen.getByTestId('authorized-members-field')).toBeTruthy();
  });

  it('should render AuthorizedMembers when user has KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS and field is editable', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      if (capabilities.includes(useGrantedModule.KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS)) return true;
      return true;
    });
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      authorizedMembers: { enabled: true, isEditable: true, defaults: [] },
    }));
    expect(screen.getByTestId('authorized-members-field')).toBeTruthy();
  });

  it('should render draftName field when enabled and editable', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      name: { enabled: true, isEditable: true, isRequired: false, defaultValue: 'Default Draft' },
    }));
    expect(screen.getByLabelText(/Draft name/i)).toBeTruthy();
  });

  it('should NOT render draftName field when not editable and no bypass', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      return true;
    });
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

  it('should NOT render draftDescription when not editable and no bypass', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      return true;
    });
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      description: { enabled: false, isEditable: false, isRequired: false },
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

  it('should NOT render ObjectAssigneeField when not editable and no bypass', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      return true;
    });
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      objectAssignee: { enabled: false, isEditable: false, isRequired: false, defaults: [] },
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
    // helpertext is rendered as a sibling <FormHelperText> for main_entity_author
    expect(screen.getByText(/Reuse/i)).toBeTruthy();
  });

  it('should render CreatedByField without helpertext for static type', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      author: { type: 'static', isEditable: true, isRequired: false, defaultValue: 'identity-1', defaultValueLabel: 'Org A' },
    }));
    expect(screen.getByTestId('created-by-field')).toBeTruthy();
    expect(screen.queryByText(/Reuse/i)).toBeNull();
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

  it('should wrap the form in the deferred creation context', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, makeMockForm({
      author: { type: 'static', isEditable: true, isRequired: false, defaultValue: 'identity-1', defaultValueLabel: 'Org A' },
    }));
    expect(screen.getByTestId('created-by-field').getAttribute('data-deferred')).toBe('true');
  });

  it('should send the submission once and disable the submit button while it is in flight', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv, user } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, defaultMockForm);
    const isFormSubmit = (operation: { request: { node: { params: { name: string } } } }) => operation.request.node.params.name === 'FormViewMutation';

    await user.click(screen.getByRole('button', { name: 'Submit' }));
    await waitFor(() => {
      expect(relayEnv.mock.getAllOperations().filter(isFormSubmit)).toHaveLength(1);
    });
    // The request is still pending: the button stays disabled and cannot send it twice
    const button = await screen.findByRole('button', { name: 'Submitting...' });
    expect(button.hasAttribute('disabled')).toBe(true);
    await user.click(button);
    expect(relayEnv.mock.getAllOperations().filter(isFormSubmit)).toHaveLength(1);
  });

  it('should show the GraphQL error of a failed submission, not the Relay wrapper', async () => {
    useGrantedSpy.mockReturnValue(true);
    const { relayEnv, user } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, defaultMockForm);

    await user.click(screen.getByRole('button', { name: 'Submit' }));
    await waitFor(() => {
      expect(relayEnv.mock.getAllOperations().filter((operation) => operation.request.node.params.name === 'FormViewMutation')).toHaveLength(1);
    });
    const error = Object.assign(
      new Error('Relay request for `FormViewMutation` failed by the following reasons:\n1. You are not allowed to create labels.'),
      { res: { errors: [{ message: 'You are not allowed to create labels.' }] } },
    );
    relayEnv.mock.rejectMostRecentOperation(error);
    expect(await screen.findByText('You are not allowed to create labels.')).toBeTruthy();
    expect(screen.queryByText(/Relay request/)).toBeNull();
  });
});

describe('FormView submission into a draft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const submitForm = async (canOpenDraft: boolean, onSuccess = vi.fn(), embedded = false) => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      if (capabilities.includes(useGrantedModule.KNOWLEDGE_KNUPDATE)) return canOpenDraft;
      return true;
    });
    const { relayEnv, user } = testRender(<FormView embedded={embedded} onSuccess={onSuccess} />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, defaultMockForm);
    await user.type(screen.getByRole('textbox', { name: /Name/ }), 'My report');
    await user.click(screen.getByRole('button', { name: 'Submit' }));
    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation({ data: { formSubmit: { success: true, message: null, entityId: 'draft-id' } } });
    });
    return { user, onSuccess };
  };

  it('opens the draft, closing the dialog first, when the user can open it', async () => {
    const { onSuccess } = await submitForm(true, vi.fn(), true);
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard/data/import/draft/draft-id');
    });
    expect(onSuccess).toHaveBeenCalled();
  });

  it('confirms the submission instead of opening a draft the user cannot open', async () => {
    await submitForm(false);
    expect(await screen.findByText('Your submission has been sent and is being processed.')).toBeTruthy();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('offers to close the dialog, and to submit again, once the submission is confirmed', async () => {
    const { user, onSuccess } = await submitForm(false, vi.fn(), true);
    await screen.findByText('Your submission has been sent and is being processed.');
    await user.click(screen.getByRole('button', { name: 'Close' }));
    expect(onSuccess).toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Submit again' }));
    expect(screen.getByRole('button', { name: 'Submit' })).toBeTruthy();
  });
});

describe('FormView objects created on the fly', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const lookupForm = (schema: object) => ({
    id: 'form-id',
    name: 'Test Form',
    description: 'Test Description',
    active: true,
    form_schema: JSON.stringify({
      fields: [],
      mainEntityType: 'Malware',
      mainEntityLookup: true,
      mainEntityMultiple: true,
      additionalEntities: [{ id: 'tools', entityType: 'Tool', label: 'Tools', lookup: true, multiple: true }],
      relationships: [],
      ...schema,
    }),
  });
  // Capabilities granted in the main scope, and in the draft scope
  const grant = (main: string[], draft: string[] = []) => {
    useGrantedSpy.mockImplementation((capabilities: string[], _matchAll?: boolean, options?: { capabilitiesInDraft?: string[] }) => {
      return capabilities.some((capability) => main.includes(capability))
        || (options?.capabilitiesInDraft ?? []).some((capability) => draft.includes(capability));
    });
  };
  const renderForm = async (schema: object) => {
    const { relayEnv, user } = testRender(<FormView />, { userContext: mockUserContext });
    await resolveAndWait(relayEnv, lookupForm(schema));
    return user;
  };
  const creationDisabled = (name: string) => screen.getByTestId(`lookup-${name}`).getAttribute('data-disable-creation');
  const draftCheckbox = () => screen.getByRole('checkbox', { name: 'Create as draft' });

  it('should not offer creation on the fly in main without Create / Update knowledge in main', async () => {
    grant([useGrantedModule.KNOWLEDGE_KNFORMINTAKE]);
    await renderForm({ isDraftByDefault: false });
    expect(creationDisabled('mainEntityLookup')).toBe('true');
    expect(creationDisabled('additional_tools_lookup')).toBe('true');
  });

  it('should offer creation on the fly in main with Create / Update knowledge in main', async () => {
    grant([useGrantedModule.KNOWLEDGE_KNFORMINTAKE, useGrantedModule.KNOWLEDGE_KNUPDATE]);
    await renderForm({ isDraftByDefault: false });
    expect(creationDisabled('mainEntityLookup')).toBe('false');
    expect(creationDisabled('additional_tools_lookup')).toBe('false');
  });

  it('should offer creation on the fly in a draft, and stop offering it once the draft is unchecked', async () => {
    grant([useGrantedModule.KNOWLEDGE_KNFORMINTAKE]);
    const user = await renderForm({ isDraftByDefault: true, allowDraftOverride: true });
    expect(creationDisabled('mainEntityLookup')).toBe('false');
    await user.click(draftCheckbox());
    expect(creationDisabled('mainEntityLookup')).toBe('true');
    expect(creationDisabled('additional_tools_lookup')).toBe('true');
  });

  it('should keep the draft while objects created on the fly are picked', async () => {
    grant([useGrantedModule.KNOWLEDGE_KNFORMINTAKE]);
    const user = await renderForm({ isDraftByDefault: true, allowDraftOverride: true });
    expect(screen.queryByText('Remove the entities created in this form to submit it outside a draft.')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'pick on the fly additional_tools_lookup' }));
    expect(draftCheckbox()).toBeDisabled();
    expect(screen.getByText('Remove the entities created in this form to submit it outside a draft.')).toBeTruthy();
  });

  it('should not force a draft on the form capability in main with Create / Update knowledge in draft only', async () => {
    grant([useGrantedModule.KNOWLEDGE_KNFORMINTAKE], [useGrantedModule.KNOWLEDGE_KNUPDATE]);
    await renderForm({ isDraftByDefault: false });
    expect(draftCheckbox()).not.toBeChecked();
    expect(draftCheckbox()).toBeEnabled();
    expect(creationDisabled('mainEntityLookup')).toBe('true');
  });

  it('should still force a draft on Create / Update knowledge in draft only, without the form capability in main', async () => {
    grant([], [useGrantedModule.KNOWLEDGE_KNUPDATE]);
    await renderForm({ isDraftByDefault: false });
    expect(draftCheckbox()).toBeChecked();
    expect(draftCheckbox()).toBeDisabled();
    expect(creationDisabled('mainEntityLookup')).toBe('false');
  });
});
