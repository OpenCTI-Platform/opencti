import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { Add } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import Fab from '@mui/material/Fab';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import StatusTemplateField from '../../common/form/StatusTemplateField';
import { StatusForm, statusValidation } from './statusFormUtils';
// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
});

const subTypeWorkflowStatusAddCreationMutation = graphql`
  mutation SubTypeWorkflowStatusAddCreationMutation(
    $id: ID!
    $input: StatusAddInput!
  ) {
    subTypeEdit(id: $id) {
      statusAdd(input: $input) {
        ...SubTypeWorkflowDrawer_subType
      }
    }
  }
`;

interface SubTypeWorkflowStatusAddProps {
  display: boolean;
  subTypeId: string;
  scope: string;
}

const SubTypeWorkflowStatusAdd: FunctionComponent<
  SubTypeWorkflowStatusAddProps
> = ({ display, subTypeId, scope }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();
  const initialValues: StatusForm = { template: null, order: '' };
  const [commit] = useApiMutation(subTypeWorkflowStatusAddCreationMutation);
  const onSubmit: FormikConfig<StatusForm>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const finalValues = {
      order: parseInt(values.order, 10),
      template_id: values.template?.value,
      scope,
    };
    commit({
      variables: {
        id: subTypeId,
        input: finalValues,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };
  return (
    <div style={{ display: display ? 'block' : 'none' }}>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Formik
        initialValues={initialValues}
        validationSchema={statusValidation(t_i18n)}
        onSubmit={onSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
          <Form>
            <Dialog
              open={open}
              onClose={handleClose}
              title={t_i18n('Create a status')}
            >
              <StatusTemplateField
                name="template"
                setFieldValue={setFieldValue}
                helpertext=""
              />
              <Field
                component={TextField}
                variant="standard"
                name="order"
                label={t_i18n('Order')}
                fullWidth={true}
                type="number"
                style={{ marginTop: 20 }}
              />
              <DialogActions>
                <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
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
    </div>
  );
};

export default SubTypeWorkflowStatusAdd;
