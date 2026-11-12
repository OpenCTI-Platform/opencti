import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { Formik, Form } from 'formik';
import testRender from '../../../../utils/tests/test-render';
import { fetchQuery } from '../../../../relay/environment';
import StatusField from './StatusField';

vi.mock('../../../../relay/environment', async () => {
  const actual = await vi.importActual('../../../../relay/environment');
  return {
    ...actual,
    fetchQuery: vi.fn(),
  };
});

vi.mock('../workflow/workflowFeatureFlag', async () => {
  const actual = await vi.importActual('../workflow/workflowFeatureFlag');
  return { ...actual, isWorkflowUiEnabledForType: () => true };
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

const renderStatusField = (props: Record<string, unknown> = {}) => {
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

  describe('with a published workflow', () => {
    const publishedWorkflowResponse = {
      workflowDefinitionPublished: true,
      workflowStatuses: [{ id: 'status-2', order: 2, type: 'Case-Incident', template: { name: 'In Progress', color: '#00ff00' } }],
    };

    beforeEach(() => {
      // The published workflow query is the one sent with an entityType variable
      fetchQueryMock.mockImplementation((_query: unknown, variables: Record<string, unknown>) => ({
        toPromise: () => Promise.resolve(variables.entityType ? publishedWorkflowResponse : mockStatusesResponse),
      }));
    });

    it('should be read-only by default', async () => {
      renderStatusField();
      await waitFor(() => expect(screen.getByLabelText('Status')).toBeDisabled());
    });

    it('should list only the workflow statuses with workflowStatusesOnly', async () => {
      const { user } = renderStatusField({ workflowStatusesOnly: true });

      await waitFor(() => {
        expect(fetchQueryMock).toHaveBeenCalledWith(expect.anything(), { entityType: 'Case-Incident', withStatuses: true });
      });
      const input = screen.getByLabelText('Status');
      expect(input).toBeEnabled();
      await user.click(input);

      expect(await screen.findByText('In Progress')).toBeInTheDocument();
      expect(screen.queryByText('Closed')).not.toBeInTheDocument();
      expect(fetchQueryMock).not.toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ filters: expect.anything() }));
    });
  });
});
