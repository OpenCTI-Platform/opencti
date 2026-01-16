import Button from '@common/button/Button';
import Tooltip from '@mui/material/Tooltip';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { InformationOutline } from 'mdi-material-ui';
import * as Yup from 'yup';
import TextField from '../../../../../components/TextField';
import FormButtonContainer from '../../../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import SwitchField from '../../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';

export interface FintelTemplateFormInputs {
  name: string;
  description: string | null;
  published: boolean;
}

export type FintelTemplateFormInputKeys = keyof FintelTemplateFormInputs;

interface FintelTemplateFormProps {
  onClose: () => void;
  onSubmit: FormikConfig<FintelTemplateFormInputs>['onSubmit'];
  onSubmitField: (field: FintelTemplateFormInputKeys, value: unknown) => void;
  defaultValues?: FintelTemplateFormInputs;
  isEdition?: boolean;
}

const FintelTemplateForm = ({
  onClose,
  onSubmit,
  onSubmitField,
  defaultValues,
  isEdition = false,
}: FintelTemplateFormProps) => {
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    published: Yup.boolean().required(t_i18n('This field is required')),
  });

  const initialValues: FintelTemplateFormInputs = defaultValues ?? {
    name: '',
    description: null,
    published: false,
  };

  const updateField = async (field: FintelTemplateFormInputKeys, value: unknown) => {
    validation.validateAt(field, { [field]: value })
      .then(() => onSubmitField(field, value))
      .catch(() => false);
  };

  const onUpdate = isEdition ? updateField : undefined;

  return (
    <Formik<FintelTemplateFormInputs>
      enableReinitialize={true}
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting }) => {
        return (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              required
              onSubmit={onUpdate}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="published"
              label={(
                <>
                  <span>{t_i18n('Template published')}</span>
                  <Tooltip title={t_i18n('If false, the template won\'t be available to generate files')}>
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ margin: '0 0 -5px 10px' }}
                    />
                  </Tooltip>
                </>
              )}
              containerstyle={{ marginTop: 20 }}
              onChange={onUpdate}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              style={fieldSpacingContainerStyle}
              multiline={true}
              rows="4"
              onSubmit={onUpdate}
            />

            {!isEdition && (
              <FormButtonContainer>
                <Button
                  disabled={isSubmitting}
                  onClick={() => {
                    handleReset();
                    onClose();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </FormButtonContainer>
            )}
          </Form>
        );
      }}
    </Formik>
  );
};

export default FintelTemplateForm;
