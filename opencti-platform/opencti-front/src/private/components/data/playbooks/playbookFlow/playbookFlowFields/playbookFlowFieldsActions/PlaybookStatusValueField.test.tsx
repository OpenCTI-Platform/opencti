import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { Formik, Form, FormikValues, useFormikContext } from 'formik';
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

let formValues: FormikValues = {};
const FormValuesSpy = () => {
  formValues = useFormikContext<FormikValues>().values;
  return null;
};

const renderField = (initialAction: PlaybookUpdateAction = action) => testRender(
  <Formik initialValues={{ actions: [initialAction], actionsFormValues: [] }} onSubmit={vi.fn()}>
    <Form>
      <PlaybookStatusValueField action={initialAction} index={0} />
      <FormValuesSpy />
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

  it('clears only the selected status when the entity type changes, keeping the other action settings', async () => {
    fetchQueryMock.mockReturnValue({ toPromise: () => Promise.resolve(page(['Case-Incident', 'Report'], null, false)) });
    const configured = {
      ...action,
      entity_type: 'Report',
      value: [{ label: 'New', value: 'status-new', patch_value: 'status-new' }],
      apply_transition_actions: true,
    } as PlaybookUpdateAction;
    const { user } = renderField(configured);

    await user.click(screen.getByLabelText(/Entity type/));
    await user.click(await screen.findByText('Incident response'));

    await waitFor(() => {
      expect(formValues.actions[0]).toEqual({
        op: 'replace',
        attribute: 'x_opencti_workflow_id',
        entity_type: 'Case-Incident',
        apply_transition_actions: true,
      });
    });
  });
});
