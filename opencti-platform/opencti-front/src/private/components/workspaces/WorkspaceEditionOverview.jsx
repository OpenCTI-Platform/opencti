import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import inject18n, { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation } from '../../../relay/environment';
import MarkdownField from '../../../components/fields/MarkdownField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

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

const WorkspaceEditionOverviewComponent = ({ workspace, context }) => {
  const { id } = workspace;
  const { t_i18n } = useFormatter();
  const initialValues = pick(['name', 'description'], workspace);

  const workspaceValidation = () => Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: workspaceEditionOverviewFocus,
      variables: {
        id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name, value) => {
    workspaceValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: workspaceMutationFieldPatch,
          variables: {
            id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={workspaceValidation()}
      onSubmit={() => true}
    >
      {() => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
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
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
              }
          />
        </Form>
      )}
    </Formik>
  );
};

WorkspaceEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  workspace: PropTypes.object,
  context: PropTypes.array,
};

const WorkspaceEditionOverview = createFragmentContainer(
  WorkspaceEditionOverviewComponent,
  {
    workspace: graphql`
      fragment WorkspaceEditionOverview_workspace on Workspace {
        id
        name
        description
        type
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(WorkspaceEditionOverview);
