import * as Yup from 'yup';
import { DialogActions } from '@mui/material';
import { CoverageInformation } from '../SecurityCoverage-types';
import { useFormatter } from '../../../../../components/i18n';
import { Field, Form, Formik } from 'formik';
import TextField from '../../../../../components/TextField';
import Button from '../../../../../components/common/button/Button';
import DateTimePickerField from '../../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { CoverageInformationFieldAdd } from '../../../common/form/CoverageInformationField';

export interface SecurityCoverageResultFormData {
  name: string;
  coverageInformation: CoverageInformation[];
  validFrom: Date | null;
  validTo: Date | null;
}

interface SecurityCoverageResultFormDetailsProps {
  onSubmit: (values: SecurityCoverageResultFormData) => void;
  onCancel: () => void;
}

const SecurityCoverageResultFormDetails = ({
  onSubmit,
  onCancel,
}: SecurityCoverageResultFormDetailsProps) => {
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
    validFrom: Yup.date().nullable().typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    validTo: Yup.date().nullable().typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    coverageInformation: Yup.array().of(
      Yup.object().shape({
        coverage_name: Yup.string().required(t_i18n('This field is required')),
        coverage_score: Yup.number()
          .required(t_i18n('This field is required'))
          .min(0, t_i18n('Score must be at least 0'))
          .max(100, t_i18n('Score must be at most 100')),
      }),
    ).min(1, t_i18n('At least one coverage metric is required')),
  });

  const initialValues: SecurityCoverageResultFormData = {
    name: '',
    validFrom: null,
    validTo: null,
    coverageInformation: [],
  };

  return (
    <Formik<SecurityCoverageResultFormData>
      enableReinitialize
      validateOnMount
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ isValid, values, setFieldValue }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            required
          />
          <CoverageInformationFieldAdd
            name="coverageInformation"
            values={values.coverageInformation}
            setFieldValue={setFieldValue}
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

          <DialogActions>
            <Button variant="secondary" onClick={onCancel}>
              {t_i18n('Cancel')}
            </Button>
            <Button
              type="submit"
              disabled={!isValid}
            >
              {t_i18n('Next')}
            </Button>
          </DialogActions>
        </Form>
      )}
    </Formik>
  );
};

export default SecurityCoverageResultFormDetails;
