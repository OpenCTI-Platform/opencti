import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import StatusTemplateField from '../../common/form/StatusTemplateField';
import { StatusCreationStatusTemplatesQuery$data } from './__generated__/StatusCreationStatusTemplatesQuery.graphql';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

export const statusCreationStatusTemplatesQuery = graphql`
  query StatusCreationStatusTemplatesQuery {
    statusTemplates {
      edges {
        node {
          id
          name
          color
        }
      }
    }
  }
`;

const statusCreationMutation = graphql`
  mutation StatusCreationMutation($id: ID!, $input: StatusAddInput!) {
    subTypeEdit(id: $id) {
      statusAdd(input: $input) {
        ...SubTypeEdition_subType
      }
    }
  }
`;

const statusValidation = (t: (name: string | object) => string) => Yup.object().shape({
  template: Yup.object().nullable().required(t('This field is required')),
  order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

interface StatusCreationProps {
  display: string,
  subTypeId: string,
}

interface FormProps {
  template: { value: string } | null,
  order: string
}

const StatusCreation: FunctionComponent<StatusCreationProps> = ({ display, subTypeId }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();
  const initialValues: FormProps = { template: null, order: '' };

  const onSubmit: FormikConfig<FormProps>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const finalValues = {
      order: parseInt(values.order, 10),
      template_id: values.template?.value,
    };
    commitMutation({
      mutation: statusCreationMutation,
      variables: {
        id: subTypeId,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
    });
  };

  return (
    <div style={{ display: display ? 'block' : 'none' }}>
      <Fab onClick={handleOpen} color="secondary" aria-label="Add" className={classes.createButton}>
        <Add />
      </Fab>
      <Formik initialValues={initialValues} validationSchema={statusValidation(t)}
              onSubmit={onSubmit} onReset={onReset}>
        {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
          <Form>
            <Dialog open={open} PaperProps={{ elevation: 1 }} onClose={handleClose} fullWidth={true}>
              <DialogTitle>{t('Create a status')}</DialogTitle>
              <DialogContent>
                <QueryRenderer
                  query={statusCreationStatusTemplatesQuery}
                  render={({ props }: { props: StatusCreationStatusTemplatesQuery$data }) => {
                    if (props && props.statusTemplates) {
                      return (
                        <StatusTemplateField name="template" setFieldValue={setFieldValue} helpertext={''} />
                      );
                    }
                    return <div />;
                  }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="order"
                  label={t('Order')}
                  fullWidth={true}
                  type="number"
                  style={{ marginTop: 20 }}
                />
              </DialogContent>
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>
                  {t('Cancel')}
                </Button>
                <Button color="secondary" onClick={submitForm} disabled={isSubmitting}>
                  {t('Create')}
                </Button>
              </DialogActions>
            </Dialog>
          </Form>
        )}
      </Formik>
    </div>
  );
};

export default StatusCreation;
