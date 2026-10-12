import * as Yup from 'yup';
import { CoverageInformationForm } from '../SecurityCoverage-types';
import { useFormatter } from '../../../../../components/i18n';
import { Field, Form, Formik } from 'formik';
import TextField from '../../../../../components/TextField';
import Button from '../../../../../components/common/button/Button';
import DateTimePickerField from '../../../../../components/DateTimePickerField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import CoverageInformationField from '../../../common/form/CoverageInformationField';
import FormButtonContainer from '@common/form/FormButtonContainer';
import CreatedByField from '../../../common/form/CreatedByField';
import ObjectLabelField from '../../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../../components/SimpleMarkdownField';
import ConfidenceField from '../../../common/form/ConfidenceField';
import { ExistingSecurityCoverageResult, findDuplicateResultField } from './SecurityCoverageResultForm-utils';

export interface SecurityCoverageResultFormData {
  name: string;
  description: string;
  confidence: number | undefined;
  createdBy?: FieldOption;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  coverageInformation: CoverageInformationForm[];
  externalUri: string;
  validFrom: Date | null;
  validTo: Date | null;
}

interface SecurityCoverageResultFormDetailsProps {
  onSubmit: (values: SecurityCoverageResultFormData) => void;
  onNext: (values: SecurityCoverageResultFormData) => void;
  onCancel: () => void;
  initValues?: SecurityCoverageResultFormData;
  existingResults?: readonly ExistingSecurityCoverageResult[] | null;
}

const SecurityCoverageResultFormDetails = ({
  onSubmit,
  onNext,
  onCancel,
  initValues,
  existingResults,
}: SecurityCoverageResultFormDetailsProps) => {
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required'))
      .test(
        'unique-name',
        t_i18n('A result with this name already exists in this security coverage'),
        function isNameUnique(name) {
          return findDuplicateResultField({ name: name ?? '', externalUri: this.parent.externalUri }, existingResults) !== 'name';
        },
      ),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    validFrom: Yup.date().nullable().typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    validTo: Yup.date()
      .min(Yup.ref('validFrom'), t_i18n("The end date can't be before start date"))
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    coverageInformation: Yup.array().of(
      Yup.object().shape({
        coverage_name: Yup.string().required(t_i18n('This field is required')),
        coverage_score: Yup.number()
          .required(t_i18n('This field is required'))
          .min(0, t_i18n('Score must be at least 0'))
          .max(100, t_i18n('Score must be at most 100')),
      }),
    ).min(1, t_i18n('At least one coverage metric is required')),
    externalUri: Yup.string().url().nullable()
      .test(
        'unique-external-uri',
        t_i18n('A result with this external link already exists in this security coverage'),
        function isExternalUriUnique(externalUri) {
          return findDuplicateResultField({ name: this.parent.name, externalUri }, existingResults) !== 'externalUri';
        },
      ),
  });

  const initialValues: SecurityCoverageResultFormData = initValues ?? {
    name: '',
    description: '',
    createdBy: undefined,
    confidence: 100,
    objectLabel: [],
    objectMarking: [],
    validFrom: null,
    validTo: null,
    coverageInformation: [
      { coverage_name: null, coverage_score: null },
    ],
    externalUri: '',
  };

  return (
    <Formik<SecurityCoverageResultFormData>
      enableReinitialize
      validateOnMount
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ isValid, setFieldValue, values }) => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows={4}
            style={fieldSpacingContainerStyle}
            autoPersistOnBlur={false}
          />
          <ConfidenceField
            containerStyle={fieldSpacingContainerStyle}
            entityType="Security-Coverage"
          />
          <Field
            component={CoverageInformationField}
            name="coverageInformation"
          />
          <Field
            component={TextField}
            name="externalUri"
            label={t_i18n('Source external link')}
            className="mt-4"
          />
          <Field
            component={DateTimePickerField}
            name="validFrom"
            textFieldProps={{
              label: t_i18n('Valid from'),
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <Field
            component={DateTimePickerField}
            name="validTo"
            textFieldProps={{
              label: t_i18n('Valid to'),
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />

          <FormButtonContainer>
            <Button variant="tertiary" onClick={onCancel}>
              {t_i18n('Cancel')}
            </Button>
            <Button
              type="submit"
              variant="secondary"
              disabled={!isValid}
            >
              {t_i18n('Create')}
            </Button>
            <Button
              type="button"
              disabled={!isValid}
              onClick={() => onNext(values)}
            >
              {t_i18n('Next')}
            </Button>
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

export default SecurityCoverageResultFormDetails;
