import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { Formik, Form } from 'formik';
import testRender from '../../../../../../../utils/tests/test-render';
import { fetchQuery } from '../../../../../../../relay/environment';
import PlaybookStatusValueField from './PlaybookStatusValueField';
import type { PlaybookUpdateAction } from './playbookAction-types';

vi.mock('../../../../../../../relay/environment', async () => {
  const actual = await vi.importActual('../../../../../../../relay/environment');
  return { ...actual, fetchQuery: vi.fn() };
});

const page = (types: string[], endCursor: string | null, hasNextPage: boolean) => ({
  statuses: {
    pageInfo: { endCursor, hasNextPage },
    edges: types.map((type) => ({ node: { type } })),
  },
});

const action: PlaybookUpdateAction = { op: 'replace', attribute: 'x_opencti_workflow_id' };

const renderField = () => testRender(
  <Formik initialValues={{ actions: [action], actionsFormValues: [] }} onSubmit={vi.fn()}>
    <Form>
      <PlaybookStatusValueField action={action} index={0} />
    </Form>
  </Formik>,
);

describe('PlaybookStatusValueField', () => {
  const fetchQueryMock = fetchQuery as Mock;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('lists the entity types of every status page, without the draft workspace', async () => {
    fetchQueryMock.mockImplementation((_query: unknown, variables: Record<string, unknown>) => ({
      toPromise: () => Promise.resolve(variables.after
        ? page(['Report'], null, false)
        : page(['Case-Incident', 'DraftWorkspace', 'Case-Incident'], 'cursor-1', true)),
    }));
    const { user } = renderField();

    await waitFor(() => {
      expect(fetchQueryMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ after: 'cursor-1' }));
    });
    await user.click(screen.getByLabelText(/Entity type/));

    expect(await screen.findByText('Incident response')).toBeInTheDocument();
    expect(screen.getByText('Report')).toBeInTheDocument();
    expect(screen.queryByText('Draft')).not.toBeInTheDocument();
  });

  it('keeps an empty type list when the statuses cannot be read', async () => {
    fetchQueryMock.mockReturnValue({ toPromise: () => Promise.reject(new Error('Forbidden')) });
    const { user } = renderField();

    await user.click(screen.getByLabelText(/Entity type/));

    expect(await screen.findByText('No available options')).toBeInTheDocument();
  });
});
