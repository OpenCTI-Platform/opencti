import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { pick } from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { StatusTemplateEdition_statusTemplate$key } from './__generated__/StatusTemplateEdition_statusTemplate.graphql';
import { useSchemaEditionValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

export const StatusTemplateEditionFragment = graphql`
  fragment StatusTemplateEdition_statusTemplate on StatusTemplate {
    id
    name
    color
  }
`;

const statusTemplateMutationFieldPatch = graphql`
  mutation StatusTemplateEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    statusTemplateFieldPatch(id: $id, input: $input) {
      id
      name
      color
    }
  }
`;

const statusTemplateEditionFocus = graphql`
  mutation StatusTemplateEditionFocusMutation($id: ID!, $input: EditContext!) {
    statusTemplateContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const OBJECT_TYPE = 'StatusTemplate';

interface StatusTemplateEditionProps {
  handleClose: () => void;
  statusTemplate: StatusTemplateEdition_statusTemplate$key;
}

const StatusTemplateEdition: FunctionComponent<StatusTemplateEditionProps> = ({
  statusTemplate,
}) => {
  const data = useFragment(StatusTemplateEditionFragment, statusTemplate);

  const { t_i18n } = useFormatter();

  const basicShape: Yup.ObjectShape = {
    name: Yup.string(),
    color: Yup.string(),
  };
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const validator = useSchemaEditionValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const initialValues = pick(['name', 'color'], data);

  const handleChangeFocus = (name: string) => {
    commitMutation({
      mutation: statusTemplateEditionFocus,
      variables: {
        id: data.id,
        input: {
          focusOn: name,
        },
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  const handleSubmitField = (name: string, value: string) => {
    validator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: statusTemplateMutationFieldPatch,
          variables: {
            id: data.id,
            input: { key: name, value: value || '' },
          },
          updater: undefined,
          optimisticUpdater: undefined,
          optimisticResponse: undefined,
          onCompleted: undefined,
          onError: undefined,
          setSubmitting: undefined,
        });
      })
      .catch(() => false);
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={validator}
      onSubmit={() => {
      }}
    >
      {() => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
          />
          <Field
            component={ColorPickerField}
            name="color"
            label={t_i18n('Color')}
            required={(mandatoryAttributes.includes('color'))}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
          />
        </Form>
      )}
    </Formik>
  );
};

export default StatusTemplateEdition;
