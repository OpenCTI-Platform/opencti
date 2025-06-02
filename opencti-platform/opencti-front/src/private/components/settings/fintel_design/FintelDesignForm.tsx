import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent, useEffect } from 'react';
import * as Yup from 'yup';
import { FintelDesign_fintelDesign$data } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import { graphql } from 'react-relay';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import { FormikConfig } from 'formik/dist/types';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ColorPickerField from '../../../../components/ColorPickerField';
import { FintelDesignFormValues } from './FintelDesign';
import { useFormatter } from '../../../../components/i18n';
import { isEmptyObject } from '../../../../utils/object';
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
    name: fintelDesign.name,
    description: fintelDesign.description,
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
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const handleFieldChange = (name: string, value: string) => {
    commitFieldPatch({
      variables: {
        id: fintelDesign.id,
        input: [{ key: name, value: (value) ?? '' }],
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
      {({ setFieldValue, values, validateForm, submitForm }) => {
        useEffect(() => {
          const validate = async () => {
            const isValid = isEmptyObject(await validateForm(values));
            if (isValid) onChange(values);
          };
          validate();
        }, [values]);

        return (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth
              setFieldValue={setFieldValue}
              onSubmit={handleFieldChange}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows={2}
              setFieldValue={setFieldValue}
              onSubmit={handleFieldChange}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={CustomFileUploader}
              name="file"
              setFieldValue={setFieldValue}
              submitForm={submitForm}
            />
            <Field
              component={ColorPickerField}
              name="gradiantFromColor"
              label={t_i18n('Background primary color')}
              placeholder={t_i18n('Default')}
              fullWidth
              setFieldValue={setFieldValue}
              onSubmit={handleFieldChange}
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
              onSubmit={handleFieldChange}
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
              onSubmit={handleFieldChange}
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
