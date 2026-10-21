import React from 'react';
import { Formik } from 'formik';
import * as Yup from 'yup';
import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { useHuntFormValidation } from './HuntCreation';
import HuntNativeQueriesField from './HuntNativeQueriesField';
import HuntTypeField from './HuntTypeField';
import { emptyHuntFormValues, type HuntFormValues } from './hunt-utils';

vi.mock('./useHuntAI', () => ({ default: () => ({ isEnterpriseEdition: true, xtmOneConfigured: true, available: true }) }));
vi.mock('./useHuntConfiguration', () => ({
  default: () => ({ minScheduleIntervalMinutes: 5, maxTimeWindowHours: 8760, maxResultsPerRun: 10000 }),
}));
vi.mock('../../../utils/hooks/useEntitySettings', () => ({
  useIsMandatoryAttribute: () => ({ mandatoryAttributes: [] }),
  useDynamicSchemaCreationValidation: (_mandatoryAttributes: string[], shape: Yup.ObjectShape) => Yup.object().shape(shape),
  yupShapeConditionalRequired: (shape: Yup.ObjectShape) => shape,
}));

// The first step of the creation drawer: the hunt type and its logic share it, with the validation of the drawer
const CreationLogicStep = ({ prefill }: { prefill: Partial<HuntFormValues> }) => {
  const { validator } = useHuntFormValidation();
  const initialValues: HuntFormValues = { ...emptyHuntFormValues(), ...prefill };
  return (
    <Formik<HuntFormValues> initialValues={initialValues} validationSchema={validator} validateOnChange onSubmit={() => undefined}>
      {({ values }) => (
        <>
          <HuntTypeField />
          {values.hunt_type === 'infrastructure'
            ? <HuntNativeQueriesField label="Fingerprint documents" infrastructure />
            : <HuntNativeQueriesField label="Native queries" />}
        </>
      )}
    </Formik>
  );
};

describe('Hunt creation', () => {
  it('should flag, not drop, a native query kept across a change of the hunt type to an internet infrastructure hunt', async () => {
    const { user } = testRender(
      <CreationLogicStep prefill={{ native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"', pipeline: '' }] }} />,
    );
    expect(screen.queryByText('Choose an internet scanning service')).not.toBeInTheDocument();
    await user.click(screen.getByTestId('hunt-type-infrastructure'));
    expect(await screen.findByText('Choose an internet scanning service')).toBeInTheDocument();
    await user.click(screen.getByTestId('hunt-type-telemetry'));
    await waitFor(() => expect(screen.queryByText('Choose an internet scanning service')).not.toBeInTheDocument());
    expect(screen.queryByText('Choose a security platform')).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: /Platform/ })).toHaveTextContent('Splunk');
  });

  it('should give a native query kept across a change of the hunt type the language of the internet scanning service picked for it', async () => {
    const { user } = testRender(
      <CreationLogicStep prefill={{ native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"', pipeline: '' }] }} />,
    );
    await user.click(screen.getByTestId('hunt-type-infrastructure'));
    expect(await screen.findByText('Choose an internet scanning service')).toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: /Platform/ }));
    await user.click(screen.getByRole('option', { name: 'Censys Platform' }));
    await waitFor(() => expect(screen.queryByText('Choose an internet scanning service')).not.toBeInTheDocument());
    expect(screen.getByRole('combobox', { name: /Query language/ })).toHaveTextContent('Internet fingerprints');
  });

  it('should flag a fingerprint document kept across a change of the hunt type to a detection rule hunt', async () => {
    const { user } = testRender(
      <CreationLogicStep prefill={{ hunt_type: 'infrastructure', native_queries: [{ platform: 'censys', language: 'fingerprint', query: 'fingerprints: []', pipeline: '' }] }} />,
    );
    await user.click(screen.getByTestId('hunt-type-telemetry'));
    expect(await screen.findByText('Choose a security platform')).toBeInTheDocument();
  });
});
