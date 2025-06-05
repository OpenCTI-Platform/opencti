import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent } from 'react';
import * as Yup from 'yup';
import { FintelDesign_fintelDesign$data } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import { graphql } from 'react-relay';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import { FormikConfig } from 'formik/dist/types';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ColorPickerField from '../../../../components/ColorPickerField';
import { FintelDesignFormValues } from './FintelDesign';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';

const fintelDesignFormFieldPatchMutation = graphql`
  mutation FintelDesignFormFieldPatchMutation($id: ID!, $input: [EditInput!], $file: Upload) {
    fintelDesignFieldPatch(id: $id, input: $input, file: $file) {
      id
      name
      file_id
      description
      gradiantFromColor
      gradiantToColor
      textColor
    }
  }
`;

interface FintelDesignFormProps {
  onChange: (val: FintelDesignFormValues) => void;
  fintelDesign: FintelDesign_fintelDesign$data;
}

const FintelDesignForm: FunctionComponent<FintelDesignFormProps> = ({ onChange, fintelDesign }) => {
  const { t_i18n } = useFormatter();

  const initialValues: FintelDesignFormValues = {
    file: null,
    gradiantFromColor: fintelDesign.gradiantFromColor,
    gradiantToColor: fintelDesign.gradiantToColor,
    textColor: fintelDesign.textColor,
  };

  const fintelDesignValidation = () => Yup.object().shape({
    gradiantFromColor: Yup.string().nullable(),
    gradiantToColor: Yup.string().nullable(),
    textColor: Yup.string().nullable(),
  });

  const [commitFieldPatch] = useApiMutation(fintelDesignFormFieldPatchMutation);

  const onSubmit: FormikConfig<FintelDesignFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);
    const { file } = values;
    const inputValues = Object.entries(values)
      .filter(([key, _]) => !['file'].includes(key))
      .map(([key, value]) => ({ key, value }));

    commitFieldPatch({
      variables: {
        id: fintelDesign.id,
        input: inputValues,
        file,
      },
      onCompleted: () => {
        setSubmitting(false);
        onChange(values);
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik<FintelDesignFormValues>
      onSubmit={onSubmit}
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={fintelDesignValidation}
      validateOnChange={true}
      validateOnBlur={true}
    >
      {({ setFieldValue, submitForm }) => {
        return (
          <Form>
            <Field
              component={CustomFileUploader}
              setFieldValue={setFieldValue}
              onChange={submitForm}
            />
            <Field
              component={ColorPickerField}
              name="gradiantFromColor"
              label={t_i18n('Background primary color')}
              placeholder={t_i18n('Default')}
              fullWidth
              setFieldValue={setFieldValue}
              onSubmit={submitForm}
              variant="standard"
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={ColorPickerField}
              name="gradiantToColor"
              label={t_i18n('Background secondary color')}
              placeholder={t_i18n('Default')}
              fullWidth
              setFieldValue={setFieldValue}
              onSubmit={submitForm}
              variant="standard"
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={ColorPickerField}
              name="textColor"
              label={t_i18n('Text color')}
              placeholder={t_i18n('Default')}
              fullWidth
              setFieldValue={setFieldValue}
              onSubmit={submitForm}
              variant="standard"
              style={fieldSpacingContainerStyle}
            />
          </Form>
        );
      }}
    </Formik>
  );
};

export default FintelDesignForm;
