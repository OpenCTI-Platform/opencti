import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ThreatActorIndividualEditionDemographics from './ThreatActorIndividualEditionDemographics';
import { ThreatActorIndividualEditionDemographics_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualEditionDemographics_ThreatActorIndividual.graphql';

const mocks = vi.hoisted(() => ({
  fieldPatch: vi.fn(),
  fetchQuery: vi.fn(),
  mandatoryAttributes: [] as string[],
  threatActorIndividual: {
    id: 'threat-actor-individual-1',
    entity_type: 'Threat-Actor-Individual',
    confidence: 100,
    date_of_birth: null,
    gender: '',
    marital_status: '',
    job_title: '',
    bornIn: { id: 'country-france', name: 'France' },
    ethnicity: { id: 'country-france', name: 'France' },
    objectMarking: [],
  },
}));

vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  useFragment: () => mocks.threatActorIndividual,
}));

vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../relay/environment')>(),
  fetchQuery: mocks.fetchQuery,
}));

vi.mock('../../../../utils/hooks/useFormEditor', () => ({
  default: () => ({ fieldPatch: mocks.fieldPatch }),
}));

vi.mock('../../../../utils/hooks/useEntitySettings', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../utils/hooks/useEntitySettings')>(),
  useIsMandatoryAttribute: () => ({ mandatoryAttributes: mocks.mandatoryAttributes }),
}));

// Keep the country controls, Formik and validation real. These unrelated fields
// and mutation definitions are outside the country selection/save path.
vi.mock('./ThreatActorIndividualEditionOverview', () => ({
  ThreatActorIndividualEditionOverviewFocus: {},
  ThreatActorIndividualMutationRelationDelete: {},
  threatActorIndividualRelationAddMutation: {},
}));
vi.mock('../../../../components/AlertConfidenceForEntity', () => ({ default: () => null }));
vi.mock('../../../../components/DateTimePickerField', () => ({ default: () => null }));
vi.mock('../../../../components/fields/markdownField/MarkdownField', () => ({ default: () => null }));
vi.mock('../../common/form/OpenVocabField', () => ({ default: () => null }));
vi.mock('../../common/form/CommitMessage', () => ({ default: () => null }));
vi.mock('../../../../components/ItemIcon', () => ({ default: () => null }));

const countryFields = [
  { name: 'bornIn', label: 'Place of Birth' },
  { name: 'ethnicity', label: 'Ethnicity' },
];

const renderDemographics = () => testRender(
  <ThreatActorIndividualEditionDemographics
    threatActorIndividualRef={{} as ThreatActorIndividualEditionDemographics_ThreatActorIndividual$key}
    enableReferences={false}
  />,
);

const getCountryControl = (label: string) => {
  const input = screen.getByRole('combobox', { name: label });
  const field = input.closest<HTMLElement>('[data-combobox-root]');
  if (!field) throw new Error(`Missing country control: ${label}`);
  return { input, field: within(field) };
};

describe('ThreatActorIndividualEditionDemographics country fields', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.mandatoryAttributes = [];
    mocks.fetchQuery.mockReturnValue({
      toPromise: () => Promise.resolve({
        countries: {
          edges: [{ node: { id: 'country-germany', name: 'Germany' } }],
        },
      }),
    });
  });

  it.each(countryFields)('clears an optional $name and saves the empty relation', async ({ name, label }) => {
    const { user } = renderDemographics();
    const { input, field } = getCountryControl(label);

    expect(input).toHaveValue('France');
    await user.click(field.getByRole('button', { name: 'Clear' }));

    await waitFor(() => expect(mocks.fieldPatch).toHaveBeenCalledExactlyOnceWith({
      variables: {
        id: 'threat-actor-individual-1',
        input: { key: name, value: [''], operation: 'replace' },
      },
    }));
    await user.tab();
    expect(input).toHaveValue('');
    expect(field.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
    const otherField = countryFields.find((field) => field.name !== name)!;
    expect(screen.getByRole('combobox', { name: otherField.label })).toHaveValue('France');
  });

  it.each(countryFields)('clears an optional $name with the keyboard', async ({ name, label }) => {
    const { user } = renderDemographics();
    const { input } = getCountryControl(label);
    await user.clear(input);
    await user.keyboard('{Backspace}');

    await waitFor(() => expect(mocks.fieldPatch).toHaveBeenCalledExactlyOnceWith({
      variables: {
        id: 'threat-actor-individual-1',
        input: { key: name, value: [''], operation: 'replace' },
      },
    }));
    await user.tab();
    expect(input).toHaveValue('');
  });

  it.each(countryFields)('keeps a mandatory $name selected', async ({ name, label }) => {
    mocks.mandatoryAttributes = [name];
    const { user } = renderDemographics();
    const { input, field } = getCountryControl(label);

    expect(field.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
    await user.clear(input);
    await user.keyboard('{Backspace}');
    await user.tab();

    expect(input).toHaveValue('France');
    expect(mocks.fieldPatch).not.toHaveBeenCalled();
  });

  it.each(countryFields)('still changes $name to another country', async ({ name, label }) => {
    const { user } = renderDemographics();
    const { input } = getCountryControl(label);
    await user.click(input);
    await user.click(await screen.findByRole('option', { name: 'Germany' }));

    await waitFor(() => expect(mocks.fieldPatch).toHaveBeenCalledExactlyOnceWith({
      variables: {
        id: 'threat-actor-individual-1',
        input: { key: name, value: ['country-germany'], operation: 'replace' },
      },
    }));
    expect(input).toHaveValue('Germany');
  });
});
