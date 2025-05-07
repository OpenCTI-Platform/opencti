import { graphql } from 'react-relay';
import { FintelDesignsLine_node$data } from '@components/settings/fintel_design/__generated__/FintelDesignsLine_node.graphql';
import React, { FunctionComponent } from 'react';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import { adaptFieldValue } from '../../../../utils/String';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';

const fintelDesignMutationFieldPatch = graphql`
  mutation FintelDesignEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      ...FintelDesignsLine_node
    }
  }
`;

interface FintelDesignEditionComponentProps {
  data: FintelDesignsLine_node$data;
  isOpen: boolean;
  onClose: () => void;
}

interface FintelDesignEditionFormData {
  name: string;
  description: string ;
  url: string ;
  gradiantFromColor: string ;
  gradiantToColor: string ;
  textColor: string;
}

const FintelDesignEdition: FunctionComponent<FintelDesignEditionComponentProps> = ({
  data,
  isOpen,
  onClose,
}) => {
  const { t_i18n } = useFormatter();

  const [commitFieldPatch] = useApiMutation(fintelDesignMutationFieldPatch);
  const initialValues: FintelDesignEditionFormData = {
    name: data.name,
    description: data.description ?? '',
    url: data.url ?? '',
    gradiantFromColor: data.gradiantFromColor ?? '',
    gradiantToColor: data.gradiantToColor ?? '',
    textColor: data.textColor ?? '',
  };

  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    url: Yup.string().nullable(),
    gradiantFromColor: Yup.string().nullable(),
    gradiantToColor: Yup.string().nullable(),
    textColor: Yup.string().nullable(),
  };

  const fintelDesignValidator = useSchemaEditionValidation(
    'FintelDesign',
    basicShape,
  );

  const onSubmit: FormikConfig<FintelDesignEditionFormData>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    const { ...otherValues } = values;
    const inputValues = Object.entries(otherValues).map(([key, value]) => ({
      key,
      value: adaptFieldValue(value),
    }));
    commitFieldPatch({
      variables: {
        id: data?.id,
        inputValues,
      },
      onCompleted: () => {
        setSubmitting(false);
        onClose();
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const handleSubmitField = (name: string, value: string) => {
    fintelDesignValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitFieldPatch({
          variables: {
            id: data.id,
            input: {
              key: name,
              value: value ?? '',
            },
          },
        });
      })
      .catch(() => false);
  };
  return (
    <Drawer
      title={t_i18n('Update the fintel design')}
      open={isOpen}
      onClose={onClose}
    >
      <Formik<FintelDesignEditionFormData>
        enableReinitialize={true}
        validateOnBlur={false}
        validateOnChange={false}
        initialValues={initialValues}
        validationSchema={fintelDesignValidator}
        onSubmit={onSubmit}
      >
        {({ submitForm, isSubmitting, setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              required
            />
            <Field
              component={MarkdownField}
              controlledSelectedTab='write'
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows={2}
              style={{ marginTop: 20 }}
            />
            <div style={{ marginTop: 20, textAlign: 'right' }}>
              <Button
                variant="contained"
                disabled={isSubmitting}
                style={{ marginLeft: 16 }}
                onClick={onClose}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
                style={{ marginLeft: 16 }}
              >
                {t_i18n('Update')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default FintelDesignEdition;
