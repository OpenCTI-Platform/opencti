import React, { useEffect } from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Field, Form, Formik } from 'formik';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as Yup from 'yup';
import { CustomFieldDef, CustomFieldStoredValue, CustomFieldValue } from '../../../../utils/customFields';
import CustomFieldsFormik from './CustomFieldsFormik';
import DynamicCustomFieldsFormik from './DynamicCustomFieldsFormik';
import CustomFieldValuesCreation from './CustomFieldValuesCreation';
import CustomFieldValuesEdition from './CustomFieldValuesEdition';
import CustomFieldValuesDisplay from './CustomFieldValuesDisplay';

const state = vi.hoisted(() => ({
  enabled: true,
  definitions: {} as Record<string, CustomFieldDef[]>,
  delayed: false,
  loaders: [] as (() => void)[],
  query: vi.fn(),
}));

vi.mock('../../../../utils/hooks/useHelper', () => ({ default: () => ({ isFeatureEnable: () => state.enabled }) }));
vi.mock('../../../../components/i18n', () => ({ useFormatter: () => ({ t_i18n: (key: string) => key, fldt: (date: string) => date }) }));
vi.mock('react-relay', () => ({ useLazyLoadQuery: (...args: unknown[]) => state.query(...args) }));
vi.mock('./CustomFieldsInput', () => ({
  customFieldDefinitionsForEntityTypeQuery: {},
  CustomFieldsLoader: ({ entityType, onLoaded }: { entityType: string; onLoaded: (definitions: CustomFieldDef[]) => void }) => {
    useEffect(() => {
      let active = true;
      const load = () => {
        if (active) onLoaded(state.definitions[entityType] ?? []);
      };
      if (state.delayed) state.loaders.push(load);
      else load();
      return () => {
        active = false;
      };
    }, [entityType]);
    return null;
  },
  CustomFieldInput: ({ definition, value, onChange, onSubmit }: {
    definition: CustomFieldDef;
    value: CustomFieldValue;
    onChange?: (value: string) => void;
    onSubmit?: (value: string) => void;
  }) => (
    <input
      aria-label={definition.label}
      value={String(value)}
      onChange={(event) => {
        onChange?.(event.target.value);
        onSubmit?.(event.target.value);
      }}
    />
  ),
}));

const definition = (id: string, entityType = 'Report', defaultValue = ''): CustomFieldDef => ({
  id, name: id, label: id, field_type: 'string', min_value: null, max_value: null, select_options: null,
  entity_type_settings: [{ entity_type: entityType, mandatory: true, default_value: defaultValue }],
});

const creationFields = (
  <Form>
    <Field name="name" aria-label="Name" />
    <CustomFieldValuesCreation />
    <button type="submit">Save</button>
  </Form>
);

beforeEach(() => {
  state.enabled = true;
  state.delayed = false;
  state.loaders = [];
  state.definitions = { Report: [definition('risk', 'Report', 'default risk')] };
  state.query.mockReset().mockImplementation((_query, { entityType }) => ({
    customFieldDefinitionsForEntityType: { edges: (state.definitions[entityType] ?? []).map((node) => ({ node })) },
  }));
});

describe.each(['Report', 'stix-core-relationship'])('%s custom-field creation', (entityType) => {
  beforeEach(() => {
    state.definitions[entityType] = [definition('risk', entityType, 'default risk')];
  });

  it('initializes defaults and serializes them without leaking UI-only state', async () => {
    const submit = vi.fn();
    render(<CustomFieldsFormik entityType={entityType} initialValues={{ name: 'report' }} validationSchema={Yup.object()} onSubmit={submit}>{creationFields}</CustomFieldsFormik>);
    expect(screen.getByLabelText('risk')).toHaveValue('default risk');
    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(submit).toHaveBeenCalled());
    expect(submit.mock.calls[0][0]).toEqual({ name: 'report', customFieldValues: [{ field_name: 'risk', value: ['default risk'] }] });
  });

  it('preserves entity validation and shows mandatory custom-field errors', async () => {
    const submit = vi.fn();
    render(<CustomFieldsFormik entityType={entityType} initialValues={{ name: '' }} validationSchema={Yup.object({ name: Yup.string().required() })} onSubmit={submit}>{creationFields}</CustomFieldsFormik>);
    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(submit).not.toHaveBeenCalled());
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'report' } });
    fireEvent.change(screen.getByLabelText('risk'), { target: { value: '' } });
    fireEvent.click(screen.getByText('Save'));
    expect(await screen.findByRole('alert')).toHaveTextContent('This field is required');
    expect(submit).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('risk'), { target: { value: 'valid' } });
    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(submit).toHaveBeenCalledTimes(1));
  });

  it('does not query or submit custom fields when the feature is disabled', async () => {
    state.enabled = false;
    const submit = vi.fn();
    render(<CustomFieldsFormik entityType={entityType} initialValues={{ name: 'report' }} onSubmit={submit}>{creationFields}</CustomFieldsFormik>);
    expect(state.query).not.toHaveBeenCalled();
    expect(screen.queryByLabelText('risk')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(submit).toHaveBeenCalled());
    expect(submit.mock.calls[0][0]).toEqual({ name: 'report' });
  });

  it('waits for definitions before mounting a fixed-type form', async () => {
    let resolve: () => void = () => {};
    const pending = new Promise<void>((done) => {
      resolve = done;
    });
    let ready = false;
    state.query.mockImplementation(() => {
      if (!ready) throw pending;
      return { customFieldDefinitionsForEntityType: { edges: state.definitions[entityType].map((node) => ({ node })) } };
    });
    render(<CustomFieldsFormik entityType={entityType} initialValues={{ name: 'report' }} onSubmit={vi.fn()}>{creationFields}</CustomFieldsFormik>);
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
    await act(async () => {
      ready = true;
      resolve();
      await pending;
    });
    expect(await screen.findByLabelText('risk')).toHaveValue('default risk');
  });

  it('keeps other inputs when switching concrete types and blocks submission until new defaults load', async () => {
    state.definitions = { City: [definition('city field', 'City', 'city default')], Country: [definition('country field', 'Country', 'country default')] };
    state.delayed = true;
    const submit = vi.fn();
    render(
      <DynamicCustomFieldsFormik typeField="type" initialValues={{ name: '', type: '' }} onSubmit={submit}>
        <Form>
          <Field name="name" aria-label="Name" />
          <Field name="type" aria-label="Type" as="select"><option value="" /><option>City</option><option>Country</option></Field>
          <CustomFieldValuesCreation />
          <button type="submit">Save</button>
        </Form>
      </DynamicCustomFieldsFormik>,
    );
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'keep name' } });
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'City' } });
    await act(async () => state.loaders.splice(0).forEach((load) => load()));
    expect(screen.getByLabelText('city field')).toHaveValue('city default');
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'Country' } });
    await act(async () => fireEvent.click(screen.getByText('Save')));
    expect(submit).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Name')).toHaveValue('keep name');
    await act(async () => state.loaders.splice(0).forEach((load) => load()));
    expect(screen.queryByLabelText('city field')).not.toBeInTheDocument();
    expect(screen.getByLabelText('country field')).toHaveValue('country default');
    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(submit).toHaveBeenCalled());
    expect(submit.mock.calls[0][0]).toEqual({ name: 'keep name', type: 'Country', customFieldValues: [{ field_name: 'country field', value: ['country default'] }] });
  });
});

describe.each(['Report', 'stix-core-relationship'])('%s custom-field edition and display', (entityType) => {
  const stored: CustomFieldStoredValue[] = [{ field_id: 'unrelated', field_name: 'unrelated', string_value: 'keep' }];

  it('stages all changes into the normal commit without making immediate mutations', async () => {
    state.definitions[entityType] = [definition('first', entityType), definition('second', entityType)];
    const patch = vi.fn();
    const submit = vi.fn();
    render(
      <Formik initialValues={{ name: 'report' }} onSubmit={submit}>
        <Form>
          <CustomFieldValuesEdition entityId="id" entityType={entityType} values={stored} fieldPatch={patch} enableReferences />
          <button type="submit">Save</button>
        </Form>
      </Formik>,
    );
    fireEvent.change(await screen.findByLabelText('first'), { target: { value: 'one' } });
    fireEvent.change(screen.getByLabelText('second'), { target: { value: 'two' } });
    expect(patch).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(submit).toHaveBeenCalled());
    expect(submit.mock.calls[0][0].custom_field_values).toEqual([
      ...stored,
      { field_id: 'first', field_name: 'first', string_value: 'one' },
      { field_id: 'second', field_name: 'second', string_value: 'two' },
    ]);
  });

  it('serializes rapid edits to different fields without losing the first change', async () => {
    state.definitions[entityType] = [definition('first', entityType), definition('second', entityType)];
    const patch = vi.fn();
    render(<Formik initialValues={{}} onSubmit={vi.fn()}><CustomFieldValuesEdition entityId="id" entityType={entityType} values={stored} fieldPatch={patch} /></Formik>);
    fireEvent.change(await screen.findByLabelText('first'), { target: { value: 'one' } });
    fireEvent.change(screen.getByLabelText('second'), { target: { value: 'two' } });
    expect(patch).toHaveBeenCalledTimes(1);
    act(() => patch.mock.calls[0][0].onCompleted());
    expect(patch).toHaveBeenCalledTimes(2);
    expect(patch.mock.calls[1][0].variables.input.value).toEqual([
      ...stored,
      { field_id: 'first', field_name: 'first', string_value: 'one' },
      { field_id: 'second', field_name: 'second', string_value: 'two' },
    ]);
  });

  it('hides existing values when the feature is disabled', () => {
    state.enabled = false;
    const { container } = render(<CustomFieldValuesDisplay entityType={entityType} values={stored} />);
    expect(container).toBeEmptyDOMElement();
    expect(state.query).not.toHaveBeenCalled();
  });
});

it('keeps relationship custom values when changing the relationship predicate', async () => {
  const entityType = 'stix-core-relationship';
  state.definitions[entityType] = [definition('risk', entityType, 'default risk')];
  const submit = vi.fn();
  render(
    <CustomFieldsFormik entityType={entityType} initialValues={{ relationship_type: 'uses' }} onSubmit={submit}>
      <Form>
        <Field name="relationship_type" aria-label="Relationship type" as="select"><option>uses</option><option>targets</option></Field>
        <CustomFieldValuesCreation />
        <button type="submit">Save</button>
      </Form>
    </CustomFieldsFormik>,
  );
  fireEvent.change(screen.getByLabelText('risk'), { target: { value: 'keep risk' } });
  fireEvent.change(screen.getByLabelText('Relationship type'), { target: { value: 'targets' } });
  expect(screen.getByLabelText('risk')).toHaveValue('keep risk');
  fireEvent.click(screen.getByText('Save'));
  await waitFor(() => expect(submit).toHaveBeenCalled());
  expect(submit.mock.calls[0][0]).toEqual({ relationship_type: 'targets', customFieldValues: [{ field_name: 'risk', value: ['keep risk'] }] });
  expect(state.query.mock.calls.every(([, variables]) => variables.entityType === entityType)).toBe(true);
});
