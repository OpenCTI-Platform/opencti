import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent, useEffect } from 'react';
import * as Yup from 'yup';
import { FintelDesign_fintelDesign$data } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import { graphql } from 'react-relay';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ColorPickerField from '../../../../components/ColorPickerField';
import { FintelDesignFormValues } from './FintelDesign';
import { useFormatter } from '../../../../components/i18n';
import { isEmptyObject } from '../../../../utils/object';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const fintelDesignFormFieldPatchMutation = graphql`
  mutation FintelDesignFormFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      id
      name
      description
      url
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
    url: fintelDesign.url,
    gradiantFromColor: fintelDesign.gradiantFromColor,
    gradiantToColor: fintelDesign.gradiantToColor,
    textColor: fintelDesign.textColor,
  };

  const fintelDesignValidation = () => Yup.object().shape({
    url: Yup.string().nullable(),
    gradiantFromColor: Yup.string().nullable(),
    gradiantToColor: Yup.string().nullable(),
    textColor: Yup.string().nullable(),
  });

  const [commitFieldPatch] = useApiMutation(fintelDesignFormFieldPatchMutation);

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
      onSubmit={() => {}}
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={fintelDesignValidation}
      validateOnChange={true}
      validateOnBlur={true}
    >
      {({ setFieldValue, values, validateForm }) => {
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
              component={TextField}
              variant="standard"
              name="url"
              label={t_i18n('Logo URL')}
              fullWidth
              setFieldValue={setFieldValue}
              onSubmit={handleFieldChange}
              style={fieldSpacingContainerStyle}
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
