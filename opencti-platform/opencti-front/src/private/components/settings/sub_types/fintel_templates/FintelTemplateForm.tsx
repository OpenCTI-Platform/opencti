import Button from '@common/button/Button';
import Tooltip from '@mui/material/Tooltip';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { InformationOutline } from 'mdi-material-ui';
import * as Yup from 'yup';
import Alert from '../../../../../components/Alert';
import TextField from '../../../../../components/TextField';
import FormButtonContainer from '../../../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../../../components/fields/markdownField/MarkdownField';
import SwitchField from '../../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';

export interface FintelTemplateFormInputs {
  name: string;
  description: string | null;
  published: boolean;
  default: boolean;
  includeCoverPageByDefault: boolean;
  includeBackPageByDefault: boolean;
}

export type FintelTemplateFormInputKeys = keyof FintelTemplateFormInputs;

interface FintelTemplateFormProps {
  onClose: () => void;
  onSubmit: FormikConfig<FintelTemplateFormInputs>['onSubmit'];
  onSubmitField: (field: FintelTemplateFormInputKeys, value: unknown) => void;
  defaultValues?: FintelTemplateFormInputs;
  editingProps?: {
    onDefaultToggle: (value: boolean, revert: () => void) => void;
  };
}

const FintelTemplateForm = ({
  onClose,
  onSubmit,
  onSubmitField,
  editingProps,
  defaultValues,
}: FintelTemplateFormProps) => {
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    published: Yup.boolean().required(t_i18n('This field is required')),
    default: Yup.boolean().required(t_i18n('This field is required')),
    includeCoverPageByDefault: Yup.boolean().required(t_i18n('This field is required')),
    includeBackPageByDefault: Yup.boolean().required(t_i18n('This field is required')),
  });

  const initialValues: FintelTemplateFormInputs = defaultValues ?? {
    name: '',
    description: null,
    published: false,
    default: false,
    includeCoverPageByDefault: true,
    includeBackPageByDefault: true,
  };

  const updateField = async (field: FintelTemplateFormInputKeys, value: unknown) => {
    const normalizedValue = ['published', 'default', 'includeCoverPageByDefault', 'includeBackPageByDefault'].includes(field)
      ? value === true || value === 'true'
      : value;
    validation.validateAt(field, { [field]: normalizedValue })
      .then(() => onSubmitField(field, normalizedValue))
      .catch(() => false);
  };

  const onUpdate = editingProps ? updateField : undefined;

  return (
    <Formik<FintelTemplateFormInputs>
      enableReinitialize={true}
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => {
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

            <Field
              component={SwitchField}
              type="checkbox"
              name="default"
              label={t_i18n('Set as default')}
              containerstyle={{ marginTop: 20 }}
              onChange={
                editingProps
                  ? (_name: string, value: unknown) => {
                      const next = value === true || value === 'true';
                      editingProps.onDefaultToggle(next, () => setFieldValue('default', !next));
                    }
                  : onUpdate
              }
            />
            <div style={{ marginTop: 20, fontWeight: 500 }}>{t_i18n('Export defaults')}</div>
            <Field
              component={SwitchField}
              type="checkbox"
              name="includeCoverPageByDefault"
              label={t_i18n('Include cover page by default')}
              containerstyle={{ marginTop: 10 }}
              onChange={onUpdate}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="includeBackPageByDefault"
              label={t_i18n('Include back page by default')}
              containerstyle={{ marginTop: 10 }}
              onChange={onUpdate}
            />
            <Alert
              style={{ marginTop: 10 }}
              content={t_i18n('These defaults pre-fill the export modal but can be overridden at export time.')}
            />

            {!editingProps && (
              <FormButtonContainer>
                <Button
                  variant="secondary"
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
