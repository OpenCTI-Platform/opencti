import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation } from '../../../relay/environment';
import MarkdownField from '../../../components/fields/MarkdownField';

export const workspaceMutationFieldPatch = graphql`
  mutation WorkspaceEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      ...WorkspaceEditionOverview_workspace
      ...Dashboard_workspace
      ...Investigation_workspace
    }
  }
`;

export const workspaceEditionOverviewFocus = graphql`
  mutation WorkspaceEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    workspaceContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const WorkspaceEditionOverviewComponent = (props) => {
  const { workspace, context } = props;
  const { t_i18n } = useFormatter();

  const workspaceValidation = () => Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: workspaceEditionOverviewFocus,
      variables: {
        id: workspace.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name, value) => {
    const sanitizedValue = value?.trim() || '';
    workspaceValidation(t_i18n)
      .validateAt(name, { [name]: sanitizedValue })
      .then(() => {
        commitMutation({
          mutation: workspaceMutationFieldPatch,
          variables: {
            id: workspace.id,
            input: { key: name, value: sanitizedValue },
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = {
    name: workspace.name || '',
    description: workspace.description || '',
  };
  return (
    <Formik
      enableReinitialize
      initialValues={initialValues}
      validationSchema={workspaceValidation}
      onSubmit={(values) => {
        handleSubmitField('name', values.name);
        handleSubmitField('description', values.description);
      }}
    >
      {() => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onFocus={(e) => handleChangeFocus('name', e.target.value)}
            onBlur={(e) => handleSubmitField('name', e.target.value)}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
              }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={() => handleChangeFocus('description')}
            onBlur={() => handleSubmitField('description')}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
              }
          />
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(
  WorkspaceEditionOverviewComponent,
  {
    workspace: graphql`
      fragment WorkspaceEditionOverview_workspace on Workspace {
        id
        name
        description
      }
    `,
  },
);
