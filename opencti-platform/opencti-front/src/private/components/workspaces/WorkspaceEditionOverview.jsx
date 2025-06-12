import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import Button from '@mui/material/Button';
import { Stack } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation } from '../../../relay/environment';
import MarkdownField from '../../../components/fields/MarkdownField';
import useDeletion from '../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../utils/store';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../components/DeleteDialog';
import WorkspacePopoverDeletionMutation from './WorkspacePopoverDeletionMutation';

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

const workspaceValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

const WorkspaceEditionOverviewComponent = ({ paginationOptions, t, workspace, context }) => {
  const { id } = workspace;
  const navigate = useNavigate();
  const initialValues = pick(['name', 'description'], workspace);

  const deletion = useDeletion({ handleClose: () => {} });
  const { deleting, setDeleting, handleOpenDelete, handleCloseDelete } = deletion;

  const [commit] = useApiMutation(WorkspacePopoverDeletionMutation);

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
    workspaceValidation(t)
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

  const submitDelete = () => {
    const { type } = workspace;
    setDeleting(true);
    commit({
      variables: { id },
      updater: (store) => {
        if (paginationOptions) {
          deleteNode(store, 'Pagination_workspaces', paginationOptions, id);
        }
      },
      onCompleted: () => {
        setDeleting(false);
        if (paginationOptions) {
          handleCloseDelete();
        } else if (type) {
          navigate(`/dashboard/workspaces/${type}s`);
        } else {
          navigate('/dashboard');
        }
      },
    });
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={workspaceValidation(t)}
      onSubmit={() => true}
    >
      {() => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t('Name')}
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
            label={t('Description')}
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
          <Stack flexDirection="row" justifyContent="flex-end" mt={2}>
            <Button
              color="error"
              variant="contained"
              onClick={handleOpenDelete}
              disabled={deleting}
            >
              {t('Delete')}
            </Button>
            <DeleteDialog
              deletion={deletion}
              submitDelete={submitDelete}
              message={workspace.type === 'investigation'
                ? t('Do you want to delete this investigation?')
                : t('Do you want to delete this dashboard?')}
            />
          </Stack>
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
