import Button from '@common/button/Button';
import { Field, Form, Formik, type FormikConfig } from 'formik';
import * as Yup from 'yup';
import TextField from '../../../../../components/TextField';
import FormButtonContainer from '../../../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../../../components/fields/markdownField/MarkdownField';
import { useFormatter } from '../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';

export interface CustomViewFormInputs {
  name: string;
  description: string | null;
}

export type CustomViewFormInputKeys = keyof CustomViewFormInputs;

interface CustomViewFormProps {
  onClose: () => void;
  onSubmit: FormikConfig<CustomViewFormInputs>['onSubmit'];
  defaultValues?: CustomViewFormInputs;
}

const CustomViewForm = ({
  onClose,
  onSubmit,
  defaultValues,
}: CustomViewFormProps) => {
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const initialValues: CustomViewFormInputs = defaultValues ?? {
    name: '',
    description: null,
  };

  return (
    <Formik<CustomViewFormInputs>
      enableReinitialize={true}
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting }) => {
        return (
          <Form>
            <Field
              autoFocus
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              required
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              style={fieldSpacingContainerStyle}
              multiline={true}
              rows="4"
            />
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
          </Form>
        );
      }}
    </Formik>
  );
};

export default CustomViewForm;
