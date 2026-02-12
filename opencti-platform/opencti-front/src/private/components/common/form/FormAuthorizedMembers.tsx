import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import AuthorizedMembersField, { AuthorizedMembersFieldValue } from '@components/common/form/AuthorizedMembersField';
import DialogActions from '@mui/material/DialogActions';
import { Field, Form, Formik } from 'formik';
import { FormikHelpers } from 'formik/dist/types';
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
  showAllMembersLine?: boolean;
  isCanUseEnable?: boolean;
  customInfoMessage?: string;
  isDraftEntity?: boolean;
}

const FormAuthorizedMembers = ({
  open,
  handleClose,
  existingAccessRules,
  onSubmit,
  owner,
  canDeactivate,
  showAllMembersLine,
  isCanUseEnable,
  customInfoMessage,
  isDraftEntity,
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
          onClose={() => {
            handleReset();
            handleClose();
          }}
          title={t_i18n('Manage access restriction')}
        >
          <Form>
            {open && ( // To trigger form initialization correctly (because removed from DOM)
              <Field
                name="authorizedMembers"
                component={AuthorizedMembersField}
                owner={owner}
                showAllMembersLine={showAllMembersLine}
                canDeactivate={canDeactivate}
                addMeUserWithAdminRights
                isCanUseEnable={isCanUseEnable}
                customInfoMessage={customInfoMessage}
                isDraftEntity={isDraftEntity}
              />
            )}
          </Form>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={() => {
                handleReset();
                handleClose();
              }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
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
