import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { useFormikContext } from 'formik';
import * as Yup from 'yup';
import testRender from '../../../../utils/tests/test-render';
import ProcedureEditionOverview from './ProcedureEditionOverview';
import type { ProcedureEditionOverview_procedure$key } from './__generated__/ProcedureEditionOverview_procedure.graphql';

type Option = { value: string; label: string };

const { mockFieldPatch, mockSaveObservables, mockSaveComponents, nextComponents, nextSelection, Empty } = vi.hoisted(() => ({
  mockFieldPatch: vi.fn(),
  mockSaveObservables: vi.fn(),
  mockSaveComponents: vi.fn(),
  nextComponents: [] as Array<Record<string, unknown>>,
  nextSelection: {} as Record<string, unknown>,
  // Fields not under test render nothing
  Empty: () => null,
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return { ...actual, useFragment: (_fragment: unknown, data: unknown) => data };
});

vi.mock('../../../../utils/hooks/useFormEditor', () => ({
  default: () => ({
    fieldPatch: mockFieldPatch,
    changeFocus: vi.fn(),
    changeKillChainPhases: vi.fn(),
    changeCreated: vi.fn(),
    changeMarking: vi.fn(),
    changeExternalReferences: vi.fn(),
  }),
}));

// Observables are has-observable relationships, saved apart from the field patch.
vi.mock('./ProcedureObservablesEditor', () => ({ saveProcedureObservables: mockSaveObservables }));

vi.mock('./ProcedureComponentsEditor', () => ({
  saveProcedureComponents: mockSaveComponents,
  searchObservables: vi.fn(),
  createTextObservable: vi.fn(),
}));

// The components field under test: a button changes the sequence to the rows the test prepared.
vi.mock('./ProcedureComponentsField', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./ProcedureComponentsField')>();
  return {
    ...actual,
    __esModule: true,
    default: ({ rows, onChange }: { rows: unknown[]; onChange: (rows: unknown) => void }) => (
      <>
        <span>{`${rows.length} component(s)`}</span>
        <button type="button" onClick={() => onChange(nextComponents)}>change components</button>
      </>
    ),
  };
});

vi.mock('../../../../utils/hooks/useEntitySettings', () => ({
  useIsMandatoryAttribute: () => ({ mandatoryAttributes: [] }),
  yupShapeConditionalRequired: (shape: Yup.ObjectShape) => shape,
  useDynamicSchemaEditionValidation: (_mandatory: string[], shape: Yup.ObjectShape) => Yup.object().shape(shape),
}));

// The ref field under test: a button selects the value the test prepared, as a pick in the search would.
vi.mock('../../common/form/StixCoreObjectsField', () => ({
  __esModule: true,
  default: ({ name, onChange }: { name: string; onChange: (name: string, value: unknown) => void }) => {
    const { setFieldValue } = useFormikContext();
    const select = () => {
      setFieldValue(name, nextSelection[name]);
      onChange(name, nextSelection[name]);
    };
    return <button type="button" onClick={select}>{`select ${name}`}</button>;
  },
}));

vi.mock('../../common/form/CommitMessage', () => ({
  __esModule: true,
  default: ({ submitForm }: { submitForm: () => void }) => <button type="button" onClick={() => submitForm()}>submit</button>,
}));

vi.mock('../../../../components/TextField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../../../components/fields/markdownField/MarkdownField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../../../components/DateTimePickerField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../../../components/AlertConfidenceForEntity', () => ({ __esModule: true, default: Empty }));
vi.mock('../../common/form/ConfidenceField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../common/form/OpenVocabField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../common/form/KillChainPhasesField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../common/form/CreatedByField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../common/form/ObjectMarkingField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../common/form/StatusField', () => ({ __esModule: true, default: Empty }));
vi.mock('../../common/form/ExternalReferencesField', () => ({ ExternalReferencesField: Empty }));
vi.mock('@components/common/custom_fields/CustomFieldValuesEdition', () => ({ __esModule: true, default: Empty }));

const observable = (id: string) => ({ node: { id, entity_type: 'Domain-Name', observable_value: `${id}.example.com` } });
const option = (id: string): Option => ({ value: id, label: id });

const procedure = {
  id: 'procedure-1',
  customFieldValues: [],
  name: 'Account discovery',
  confidence: 50,
  entity_type: 'Procedure',
  description: '',
  x_procedure_type: null,
  x_mitre_platforms: [],
  first_observed: null,
  last_observed: null,
  x_execution_start: null,
  x_execution_end: null,
  killChainPhases: [],
  procedureCommand: { id: 'process-1', entity_type: 'Process', observable_value: 'whoami' },
  procedureObservables: { edges: [observable('obs-1'), observable('obs-2')] },
  procedureSources: [{ id: 'source-1', entity_type: 'Organization', name: 'Source' }],
  procedureComponents: [],
  createdBy: null,
  objectMarking: [],
  externalReferences: { edges: [{ node: { id: 'ext-1', source_name: 'mitre', description: null, url: 'https://example.com', external_id: null } }] },
  status: { id: 'status-1', order: 1, template: { name: 'New', color: '#ffffff' } },
  workflowEnabled: false,
} as unknown as ProcedureEditionOverview_procedure$key;

const renderForm = (enableReferences = false) => testRender(
  <ProcedureEditionOverview data={procedure} enableReferences={enableReferences} handleClose={() => {}} />,
);

const patchedInputs = () => mockFieldPatch.mock.calls.map(([{ variables }]) => variables.input);

describe('Component: ProcedureEditionOverview, ref fields', () => {
  beforeEach(() => {
    mockFieldPatch.mockReset();
    mockSaveObservables.mockReset();
  });

  it('removes the has-observable relationship of the observable taken out of the selection', async () => {
    nextSelection.procedureObservables = [option('obs-1')];
    renderForm();
    fireEvent.click(screen.getByText('select procedureObservables'));
    await waitFor(() => expect(mockSaveObservables).toHaveBeenCalledTimes(1));
    expect(mockSaveObservables).toHaveBeenCalledWith('procedure-1', { added: [], removed: ['obs-2'] });
    expect(mockFieldPatch).not.toHaveBeenCalled();
  });

  it('adds a has-observable relationship for the observable put in the selection', async () => {
    nextSelection.procedureObservables = [option('obs-1'), option('obs-2'), option('obs-3')];
    renderForm();
    fireEvent.click(screen.getByText('select procedureObservables'));
    await waitFor(() => expect(mockSaveObservables).toHaveBeenCalledTimes(1));
    expect(mockSaveObservables).toHaveBeenCalledWith('procedure-1', { added: ['obs-3'], removed: [] });
    expect(mockFieldPatch).not.toHaveBeenCalled();
  });

  it('patches the sources with the changed ids only', async () => {
    nextSelection.procedureSources = [option('source-2')];
    renderForm();
    fireEvent.click(screen.getByText('select procedureSources'));
    await waitFor(() => expect(mockFieldPatch).toHaveBeenCalledTimes(1));
    expect(patchedInputs()).toEqual([[
      { key: 'procedureSources', value: ['source-2'], operation: 'add' },
      { key: 'procedureSources', value: ['source-1'], operation: 'remove' },
    ]]);
  });

  it('sets the single command to the selected one', async () => {
    nextSelection.procedureCommand = null;
    renderForm();
    fireEvent.click(screen.getByText('select procedureCommand'));
    await waitFor(() => expect(mockFieldPatch).toHaveBeenCalledTimes(1));
    expect(patchedInputs()).toEqual([[{ key: 'procedureCommand', value: [] }]]);
  });

  it('saves the changed observables on submit when references are enforced, outside the field patch', async () => {
    nextSelection.procedureObservables = [option('obs-1')];
    renderForm(true);
    fireEvent.click(screen.getByText('select procedureObservables'));
    expect(mockFieldPatch).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('submit'));
    await waitFor(() => expect(mockFieldPatch).toHaveBeenCalledTimes(1));
    const [input] = patchedInputs();
    const refInputs = input.filter(({ key }: { key: string }) => ['procedureObservables', 'procedureSources', 'externalReferences'].includes(key));
    expect(refInputs).toEqual([]);
    expect(mockSaveObservables).toHaveBeenCalledWith('procedure-1', { added: [], removed: ['obs-2'] });
  });
});

describe('Component: ProcedureEditionOverview, components', () => {
  const component = (id: string, type: string) => ({ id, entity_type: 'Text', observable_value: id, type });

  beforeEach(() => {
    mockFieldPatch.mockReset();
    mockSaveComponents.mockReset();
    mockSaveComponents.mockResolvedValue(undefined);
  });

  it('puts back the sequence the platform holds when a save is refused', async () => {
    mockSaveComponents.mockRejectedValue(new Error('refused'));
    nextComponents.splice(0, nextComponents.length, component('wbadmin', 'primary'), component('quiet', 'secondary'));
    renderForm();
    fireEvent.click(screen.getByText('change components'));
    await waitFor(() => expect(mockSaveComponents).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByText('0 component(s)')).toBeDefined());
  });

  it('saves the sequence as soon as it changes', async () => {
    nextComponents.splice(0, nextComponents.length, component('wbadmin', 'primary'), component('quiet', 'secondary'));
    renderForm();
    fireEvent.click(screen.getByText('change components'));
    await waitFor(() => expect(mockSaveComponents).toHaveBeenCalledTimes(1));
    expect(mockSaveComponents).toHaveBeenCalledWith('procedure-1', [{ id: 'wbadmin', type: 'primary' }, { id: 'quiet', type: 'secondary' }]);
  });

  it('saves nothing while the first component is secondary', async () => {
    nextComponents.splice(0, nextComponents.length, component('quiet', 'secondary'), component('wbadmin', 'primary'));
    renderForm();
    fireEvent.click(screen.getByText('change components'));
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(mockSaveComponents).not.toHaveBeenCalled();
  });

  it('saves the sequence with the commit under enforced references', async () => {
    nextComponents.splice(0, nextComponents.length, component('wbadmin', 'primary'));
    renderForm(true);
    fireEvent.click(screen.getByText('change components'));
    expect(mockSaveComponents).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('submit'));
    await waitFor(() => expect(mockSaveComponents).toHaveBeenCalledWith('procedure-1', [{ id: 'wbadmin', type: 'primary' }]));
  });
});
