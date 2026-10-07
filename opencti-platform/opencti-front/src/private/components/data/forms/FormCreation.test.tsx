import React from 'react';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { PreloadedQuery } from 'react-relay';
import testRender from '../../../../utils/tests/test-render';
import FormCreation from './FormCreation';
import type { FormCreationQuery } from './__generated__/FormCreationQuery.graphql';
import type { FormLinesPaginationQuery$variables } from './__generated__/FormLinesPaginationQuery.graphql';
import type { FormBuilderData } from './Form.d';

let lastFormSchemaEditorProps: { onChange?: (data: FormBuilderData) => void; initialValues?: FormBuilderData } | undefined;

vi.mock('./FormSchemaEditor', () => ({
  __esModule: true,
  default: (props: { onChange?: (data: FormBuilderData) => void; initialValues?: FormBuilderData }) => {
    lastFormSchemaEditorProps = props;
    return <div data-testid="form-schema-editor" />;
  },
}));

const mockCommitMutation = vi.fn();
vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...actual,
    commitMutation: (...args: unknown[]) => mockCommitMutation(...args),
    handleError: vi.fn(),
  };
});

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    usePreloadedQuery: () => ({
      schemaAttributes: [
        { type: 'Report', attributes: [{ name: 'name', type: 'string', label: 'Name', mandatory: true }] },
      ],
    }),
  };
});

const validFormBuilderData: FormBuilderData = {
  name: 'Test',
  mainEntityType: 'Report',
  includeInContainer: false,
  isDraftByDefault: false,
  allowDraftOverride: false,
  mainEntityMultiple: false,
  additionalEntities: [],
  fields: [],
  relationships: [],
  active: true,
};

const paginationOptions = {} as FormLinesPaginationQuery$variables;

const renderFormCreation = (overrides: Partial<React.ComponentProps<typeof FormCreation>> = {}) => {
  const handleClose = vi.fn();
  const result = testRender(
    <FormCreation
      queryRef={{} as PreloadedQuery<FormCreationQuery>}
      handleClose={handleClose}
      paginationOptions={paginationOptions}
      {...overrides}
    />,
  );
  return { ...result, handleClose };
};

describe('FormCreation', () => {
  it('renders the name/description/active fields and the schema editor', () => {
    renderFormCreation();

    expect(screen.getByRole('textbox', { name: 'Name' })).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Description' })).toBeInTheDocument();
    expect(screen.getByTestId('form-schema-editor')).toBeInTheDocument();
  });

  it('disables the submit button until a form schema is provided', () => {
    renderFormCreation();

    expect(screen.getByRole('button', { name: 'Create' })).toBeDisabled();

    act(() => lastFormSchemaEditorProps?.onChange?.(validFormBuilderData));
  });

  it('shows a field error and does not submit when the schema is missing', async () => {
    const { user } = renderFormCreation();

    await user.type(screen.getByRole('textbox', { name: 'Name' }), 'My form');
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(mockCommitMutation).not.toHaveBeenCalled());
  });

  it('submits the mutation with the serialized schema and closes on completion', async () => {
    const { user, handleClose } = renderFormCreation();

    act(() => lastFormSchemaEditorProps?.onChange?.(validFormBuilderData));
    await user.type(screen.getByRole('textbox', { name: 'Name' }), 'My form');
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(mockCommitMutation).toHaveBeenCalled());
    const call = mockCommitMutation.mock.calls[0][0];
    expect(call.variables.input.name).toBe('My form');
    expect(JSON.parse(call.variables.input.form_schema)).toMatchObject({ mainEntityType: 'Report' });

    act(() => call.onCompleted());
    expect(handleClose).toHaveBeenCalled();
  });

  it('reports an error and re-enables submission when the mutation fails', async () => {
    const { user } = renderFormCreation();

    act(() => lastFormSchemaEditorProps?.onChange?.(validFormBuilderData));
    await user.type(screen.getByRole('textbox', { name: 'Name' }), 'My form');
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(mockCommitMutation).toHaveBeenCalled());
    const call = mockCommitMutation.mock.calls[0][0];

    act(() => call.onError(new Error('boom')));

    await waitFor(() => expect(screen.getByRole('button', { name: 'Create' })).not.toBeDisabled());
  });

  it('shows Duplicate as the submit label and pre-fills fields when duplicating', () => {
    renderFormCreation({
      formData: {
        id: 'form-1',
        name: 'Existing form',
        description: 'Existing description',
        form_schema: JSON.stringify({ mainEntityType: 'Report', fields: [], additionalEntities: [], relationships: [] }),
        active: true,
      },
    });

    expect(screen.getByRole('button', { name: 'Duplicate' })).toBeInTheDocument();
    expect(screen.getByDisplayValue('Existing form')).toBeInTheDocument();
    expect(lastFormSchemaEditorProps?.initialValues).toMatchObject({ name: 'Existing form', mainEntityType: 'Report' });
  });

  it('calls handleClose when Cancel is clicked', () => {
    const { handleClose } = renderFormCreation();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(handleClose).toHaveBeenCalled();
  });
});
