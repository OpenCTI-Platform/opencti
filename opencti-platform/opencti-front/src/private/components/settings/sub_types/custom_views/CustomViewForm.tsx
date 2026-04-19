import Button from '@common/button/Button';
import { Field, Form, Formik, type FormikConfig } from 'formik';
import * as Yup from 'yup';
import TextField from '../../../../../components/TextField';
import FormButtonContainer from '../../../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../../../components/fields/markdownField/MarkdownField';
import { useFormatter } from '../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import SwitchField from '../../../../../components/fields/SwitchField';
import { Stack } from '@mui/material';

export interface CustomViewFormInputs {
  name: string;
  description?: string | null;
  enabled?: boolean | null;
}

export type CustomViewFormInputKeys = keyof CustomViewFormInputs;

const DEFAULT_VALUES: CustomViewFormInputs = {
  name: '',
  description: null,
  enabled: false,
};

interface CustomViewFormProps {
  onClose: () => void;
  onSubmit: FormikConfig<CustomViewFormInputs>['onSubmit'];
  onSubmitField: (name: string, value: unknown) => void;
  values?: CustomViewFormInputs;
  isEdition?: boolean;
}

const CustomViewForm = ({
  onClose,
  onSubmit,
  onSubmitField,
  values,
  isEdition = false,
}: CustomViewFormProps) => {
  const { t_i18n } = useFormatter();

  const validators = {
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    enabled: Yup.boolean().nullable(),
  };

  const validation = Yup.object().shape(validators);

  const handleFieldSubmit = (
    setSubmitting: (v: boolean) => void,
  ) => (name: keyof typeof validators, value: unknown) => {
    onSubmitField(name, validators[name].cast(value));
    setSubmitting(false);
  };

  const initialValues = values ?? DEFAULT_VALUES;
  return (
    <Formik<CustomViewFormInputs>
      enableReinitialize={true}
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting, setSubmitting }) => {
        return (
          <Form>
            <Stack gap={1}>
              <Field
                autoFocus
                component={TextField}
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
                required
                onSubmit={handleFieldSubmit(setSubmitting)}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                style={fieldSpacingContainerStyle}
                multiline={true}
                rows="4"
                onSubmit={handleFieldSubmit(setSubmitting)}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="enabled"
                label={t_i18n('Make this view visible to users')}
                onChange={handleFieldSubmit(setSubmitting)}
              />
              {!isEdition && (
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
            </Stack>
          </Form>
        );
      }}
    </Formik>
  );
};

export default CustomViewForm;
