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
import { DraftCreationMutation$variables } from '@components/drafts/__generated__/DraftCreationMutation.graphql';
import { DraftWorkspaceCreationMutation } from '@components/common/files/draftWorkspace/__generated__/DraftWorkspaceCreationMutation.graphql';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../../relay/environment';

const draftWorkspaceCreationMutation = graphql`
  mutation DraftWorkspaceCreationMutation($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
      name
    }
  }
`;

interface DraftWorkspaceCreationProps {
  openCreate: boolean;
  handleCloseCreate: () => void;
  onCompleted?: () => void;
  entityId?: string;
}

interface DraftAddInput {
  name: string;
}

const DraftWorkspaceCreation: FunctionComponent<DraftWorkspaceCreationProps> = ({
  openCreate,
  handleCloseCreate,
  onCompleted,
  entityId,
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<DraftWorkspaceCreationMutation>(
    draftWorkspaceCreationMutation,
    undefined,
  );

  const draftValidation = () => Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
  });

  const onSubmit: FormikConfig<DraftAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: DraftCreationMutation$variables['input'] = {
      name: values.name,
      entity_id: entityId,
    };
    commit({
      variables: {
        input,
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
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
            open={openCreate}
            onClose={handleCloseCreate}
            fullWidth
          >
            <DialogTitle>{t_i18n('Create a draft workspace')}</DialogTitle>
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

export default DraftWorkspaceCreation;
