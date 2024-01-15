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
import { Creator } from '../../../../utils/authorizedMembers';

export interface FormAuthorizedMembersInputs {
  authorizedMembers: AuthorizedMembersFieldValue;
}

interface FormAuthorizedMembersProps {
  open: boolean;
  handleClose: () => void;
  existingAccessRules: FormAuthorizedMembersInputs['authorizedMembers'];
  onSubmit: (
    values: FormAuthorizedMembersInputs,
    helpers: FormikHelpers<FormAuthorizedMembersInputs>,
  ) => void;
  owner?: Creator;
  canDeactivate?: boolean;
}

const FormAuthorizedMembers = ({
  open,
  handleClose,
  existingAccessRules,
  onSubmit,
  owner,
  canDeactivate,
}: FormAuthorizedMembersProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Formik<FormAuthorizedMembersInputs>
      enableReinitialize
      initialValues={{
        authorizedMembers: existingAccessRules,
      }}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting, dirty, handleReset }) => (
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
          <DialogTitle>{t_i18n('Manage access restriction')}</DialogTitle>
          <DialogContent>
            <Form>
              <Field
                name="authorizedMembers"
                component={AuthorizedMembersField}
                owner={owner}
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
              {t_i18n('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting || !dirty}
            >
              {t_i18n('Save')}
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Formik>
  );
};

export default FormAuthorizedMembers;
