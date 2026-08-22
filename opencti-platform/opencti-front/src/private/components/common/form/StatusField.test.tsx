import { screen, waitFor } from '@testing-library/react';
import { Form, Formik } from 'formik';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { fetchQuery } from '../../../../relay/environment';
import type { UserContextType } from '../../../../utils/hooks/useAuth';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StatusField from './StatusField';

vi.mock('../../../../relay/environment', async () => {
  const actual = await vi.importActual('../../../../relay/environment');
  return {
    ...actual,
    fetchQuery: vi.fn(),
  };
});

const mockStatusesResponse = {
  statuses: {
    edges: [
      {
        node: {
          id: 'status-1',
          order: 1,
          type: 'Case-Incident',
          template: { name: 'New', color: '#ff0000' },
        },
      },
      {
        node: {
          id: 'status-2',
          order: 2,
          type: 'Case-Incident',
          template: { name: 'In Progress', color: '#00ff00' },
        },
      },
      {
        node: {
          id: 'status-3',
          order: 3,
          type: 'Case-Incident',
          template: { name: 'Closed', color: '#0000ff' },
        },
      },
    ],
  },
};

const renderStatusField = (props: Record<string, unknown> = {}, userContext?: Partial<UserContextType>) => {
  return testRender(
    <Formik
      initialValues={{ x_opencti_workflow_id: null }}
      onSubmit={vi.fn()}
    >
      <Form>
        <StatusField
          name="x_opencti_workflow_id"
          type="Case-Incident"
          {...props}
        />
      </Form>
    </Formik>,
    userContext ? { userContext } : undefined,
  );
};

describe('StatusField', () => {
  const fetchQueryMock = fetchQuery as Mock;

  beforeEach(() => {
    vi.clearAllMocks();
    fetchQueryMock.mockReturnValue({
      toPromise: () => Promise.resolve(mockStatusesResponse),
    });
  });

  it('should render with Status label', () => {
    renderStatusField();
    expect(screen.getByLabelText('Status')).toBeInTheDocument();
  });

  it('should call fetchQuery on focus to load statuses', async () => {
    const { user } = renderStatusField();

    const input = screen.getByLabelText('Status');
    await user.click(input);

    await waitFor(() => {
      expect(fetchQueryMock).toHaveBeenCalled();
    });
  });

  it('should render with a default status', () => {
    const defaultStatus = {
      id: 'status-1',
      order: 1,
      type: 'Case-Incident',
      template: { name: 'New', color: '#ff0000' },
    };

    renderStatusField({ defaultStatus });
    expect(screen.getByLabelText('Status')).toBeInTheDocument();
  });

  it('should pass filters with type and scope when type is provided', async () => {
    const { user } = renderStatusField({ scope: 'GLOBAL' });

    const input = screen.getByLabelText('Status');
    await user.click(input);

    await waitFor(() => {
      expect(fetchQueryMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          filters: expect.objectContaining({
            mode: 'and',
            filters: expect.arrayContaining([
              { key: 'type', values: ['Case-Incident'] },
              { key: 'scope', values: ['GLOBAL'] },
            ]),
          }),
        }),
      );
    });
  });
});

describe('StatusField - workflow read-only guard', () => {
  const fetchQueryMock = fetchQuery as Mock;

  const withWorkflowDefinitionPublished = (hasPublishedWorkflowDefinition: boolean) => {
    fetchQueryMock.mockImplementation((_query: unknown, variables: { entityType?: string }) => {
      if (variables?.entityType) {
        return { toPromise: () => Promise.resolve({ workflowDefinitionPublished: hasPublishedWorkflowDefinition }) };
      }
      return { toPromise: () => Promise.resolve(mockStatusesResponse) };
    });
  };

  const enabledFlagUserContext = () => createMockUserContext({
    settings: { platform_feature_flags: [{ id: 'ENTITIES_WORKFLOW', enable: true }] },
  }) as Partial<UserContextType>;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('keeps the field editable when the ENTITIES_WORKFLOW flag is disabled, even if a published WorkflowDefinition exists for the type', async () => {
    withWorkflowDefinitionPublished(true);

    renderStatusField({ type: 'StixSightingRelationship' });

    await waitFor(() => {
      expect(screen.getByLabelText('Status')).not.toBeDisabled();
    });
  });

  it('keeps the field editable when the flag is enabled but no published WorkflowDefinition exists for the type', async () => {
    withWorkflowDefinitionPublished(false);

    renderStatusField({ type: 'StixSightingRelationship' }, enabledFlagUserContext());

    await waitFor(() => {
      expect(fetchQueryMock).toHaveBeenCalledWith(
        expect.anything(),
        { entityType: 'StixSightingRelationship' },
      );
    });
    expect(screen.getByLabelText('Status')).not.toBeDisabled();
  });

  it('renders the field read-only when the flag is enabled and a published WorkflowDefinition exists for the type', async () => {
    withWorkflowDefinitionPublished(true);

    renderStatusField({ type: 'StixSightingRelationship' }, enabledFlagUserContext());

    await waitFor(() => {
      expect(screen.getByLabelText('Status')).toBeDisabled();
    });
  });
});

