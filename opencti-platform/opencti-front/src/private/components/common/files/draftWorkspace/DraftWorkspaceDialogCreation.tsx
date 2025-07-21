import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../../relay/environment';
import { insertNode } from '../../../../../utils/store';
import { DraftWorkspaceDialogCreationMutation, DraftWorkspaceDialogCreationMutation$variables } from './__generated__/DraftWorkspaceDialogCreationMutation.graphql';

const draftWorkspaceDialogCreationMutation = graphql`
  mutation DraftWorkspaceDialogCreationMutation($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
      name
      ...Drafts_node
    }
  }
`;

interface DraftWorkspaceCreationProps {
  openCreate?: boolean;
  handleCloseCreate?: () => void
  entityId?: string;
  paginationOptions: DraftsLinesPaginationQuery$variables
}

interface DraftAddInput {
  name: string;
}

const DraftWorkspaceDialogCreation: FunctionComponent<DraftWorkspaceCreationProps> = ({
  openCreate,
  handleCloseCreate,
  entityId,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<DraftWorkspaceDialogCreationMutation>(
    draftWorkspaceDialogCreationMutation,
    undefined,
  );

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_draftWorkspaces',
    paginationOptions,
    'draftWorkspaceAdd',
  );

  const draftValidation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
  });

  const onSubmit: FormikConfig<DraftAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: DraftWorkspaceDialogCreationMutation$variables['input'] = {
      name: values.name,
      entity_id: entityId,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        updater(store);
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={{ name: '' }}
      validationSchema={draftValidation}
      onSubmit={onSubmit}
      onReset={handleCloseCreate}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={!!openCreate}
            onClose={handleCloseCreate}
            fullWidth
          >
            <DialogTitle>{t_i18n('Create a Draft')}</DialogTitle>
            <DialogContent>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth
              />
            </DialogContent>
            <DialogActions>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                type="submit"
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </DialogActions>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default DraftWorkspaceDialogCreation;
