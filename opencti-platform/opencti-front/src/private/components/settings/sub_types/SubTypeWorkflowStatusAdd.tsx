import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import { graphql } from 'react-relay';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import StatusTemplateField from '../../common/form/StatusTemplateField';
import { StatusForm, statusValidation } from './statusFormUtils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
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
        ...SubTypeWorkflow_subType
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
              slotProps={{ paper: { elevation: 1 } }}
              onClose={handleClose}
              fullWidth={true}
            >
              <DialogTitle>{t_i18n('Create a status')}</DialogTitle>
              <DialogContent>
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
              </DialogContent>
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
