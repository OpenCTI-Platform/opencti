import { screen } from '@testing-library/react';
import { FormikConfig, FormikValues } from 'formik';
import * as Yup from 'yup';
import { describe, expect, it, vi } from 'vitest';
import { DeferredCreationContext } from '../../../../utils/hooks/useDeferredCreation';
import testRender from '../../../../utils/tests/test-render';
import { ReportCreationForm } from './ReportCreation';

// Only the "Create and map" button is under test: everything else is stubbed away.

// Custom fields are separately tested and need a relay query: use the plain Formik
vi.mock('@components/common/custom_fields/CustomFieldsFormik', async () => {
  const { Formik } = await import('formik');
  return {
    __esModule: true,
    default: ({ entityType: _entityType, enabled: _enabled, ...props }: FormikConfig<FormikValues> & { entityType?: string; enabled?: boolean }) => <Formik {...props} />,
  };
});
vi.mock('@components/common/custom_fields/CustomFieldValuesCreation', () => ({ __esModule: true, default: () => null }));

// A report that already has a content, which is what offers to map it
vi.mock('../../../../utils/hooks/useDefaultValues', () => ({
  __esModule: true,
  default: (_id: string, initialValues: object) => ({ ...initialValues, content: '<p>content</p>' }),
}));

vi.mock('../../../../utils/hooks/useEntitySettings', () => ({
  useIsMandatoryAttribute: () => ({ mandatoryAttributes: [] }),
  useDynamicSchemaCreationValidation: (_mandatoryAttributes: string[], shape: Yup.ObjectShape) => Yup.object().shape(shape),
  yupShapeConditionalRequired: (shape: Yup.ObjectShape) => shape,
}));

vi.mock('@components/common/form/AuthorizedMembersField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../common/form/CreatedByField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../common/form/ObjectLabelField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../common/form/ObjectMarkingField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../common/form/ObjectAssigneeField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../common/form/ObjectParticipantField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../common/form/OpenVocabField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../common/form/ConfidenceField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../common/form/ExternalReferencesField', () => ({ ExternalReferencesField: () => null }));
vi.mock('../../common/files/CustomFileUploader', () => ({ __esModule: true, default: () => null }));
vi.mock('../../../../components/DateTimePickerField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../../../components/fields/RichTextField', () => ({ __esModule: true, default: () => null }));
vi.mock('../../../../components/fields/markdownField/MarkdownField', () => ({ __esModule: true, default: () => null }));

describe('ReportCreationForm', () => {
  const renderForm = (isDeferredMode?: boolean) => {
    const form = <ReportCreationForm updater={vi.fn()} />;
    return testRender(isDeferredMode === undefined
      ? form
      : (
          <DeferredCreationContext.Provider value={{ isDeferredMode, captureInput: vi.fn(), registerPending: vi.fn(), getPending: vi.fn() }}>
            {form}
          </DeferredCreationContext.Provider>
        ));
  };

  it('offers to create and map a report that has a content', () => {
    renderForm();
    expect(screen.getByText('Create and map')).toBeTruthy();
  });

  it('does not offer to create and map in a form intake, there is no report to map yet', () => {
    renderForm(true);
    expect(screen.getByText('Create')).toBeTruthy();
    expect(screen.queryByText('Create and map')).toBeNull();
  });
});
