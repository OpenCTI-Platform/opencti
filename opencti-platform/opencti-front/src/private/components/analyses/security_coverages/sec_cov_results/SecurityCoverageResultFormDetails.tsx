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
}

const SecurityCoverageResultFormDetails = ({
  onSubmit,
  onNext,
  onCancel,
  initValues,
}: SecurityCoverageResultFormDetailsProps) => {
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
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
    externalUri: Yup.string().url().nullable(),
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
              type="button"
              variant="secondary"
              disabled={!isValid}
              onClick={() => onNext(values)}
            >
              {t_i18n('Next')}
            </Button>
            <Button
              type="submit"
              disabled={!isValid}
            >
              {t_i18n('Create')}
            </Button>
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

export default SecurityCoverageResultFormDetails;
