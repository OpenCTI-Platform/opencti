import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import React from 'react';
import { FormikHelpers } from 'formik/dist/types';
import AuthorizedMembersField, { AuthorizedMembersFieldValue } from '@components/common/form/AuthorizedMembersField';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';

export interface FormAuthorizedMembersInputs {
  authorizedMembers: AuthorizedMembersFieldValue;
}

interface FormAuthorizedMembersProps {
  open: boolean;
  handleClose: () => void;
  existingAccessRules: FormAuthorizedMembersInputs['authorizedMembers']
  onSubmit: (
    values: FormAuthorizedMembersInputs,
    helpers: FormikHelpers<FormAuthorizedMembersInputs>
  ) => void
  ownerId?: string
  canDeactivate?: boolean
}

const FormAuthorizedMembers = ({
  open,
  handleClose,
  existingAccessRules,
  onSubmit,
  ownerId,
  canDeactivate,
}: FormAuthorizedMembersProps) => {
  const { t } = useFormatter();

  return (
    <Formik<FormAuthorizedMembersInputs>
      enableReinitialize
      initialValues={{
        authorizedMembers: existingAccessRules,
      }}
      onSubmit={onSubmit}
    >
      {({
        submitForm,
        isSubmitting,
        dirty,
        handleReset,
      }) => (
        <Dialog
          open={open}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          maxWidth="sm"
          fullWidth={true}
          onClose={() => {
            handleReset();
            handleClose();
          }}
        >
          <DialogTitle>{t('Manage access restriction')}</DialogTitle>
          <DialogContent>
            <Form>
              <Field
                name="authorizedMembers"
                component={AuthorizedMembersField}
                ownerId={ownerId}
                showAllMembersLine
                canDeactivate={canDeactivate}
              />
            </Form>
          </DialogContent>

          <DialogActions>
            <Button
              onClick={() => {
                handleReset();
                handleClose();
              }}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={submitForm}
              disabled={
                isSubmitting
                || !dirty
              }
            >
              {t('Save')}
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Formik>
  );
};

export default FormAuthorizedMembers;
