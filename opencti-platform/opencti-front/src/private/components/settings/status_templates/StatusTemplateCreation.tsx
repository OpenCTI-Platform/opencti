import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import { Theme } from '../../../../components/Theme';
import { StatusTemplateCreationContextualMutation$data } from './__generated__/StatusTemplateCreationContextualMutation.graphql';
import { StatusTemplatesLinesPaginationQuery$variables } from './__generated__/StatusTemplatesLinesPaginationQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  dialog: {
    overflow: 'hidden',
  },
}));

const statusTemplateMutation = graphql`
  mutation StatusTemplateCreationMutation($input: StatusTemplateAddInput!) {
    statusTemplateAdd(input: $input) {
      ...StatusTemplateLine_node
    }
  }
`;

const statusTemplateContextualMutation = graphql`
  mutation StatusTemplateCreationContextualMutation(
    $input: StatusTemplateAddInput!
  ) {
    statusTemplateAdd(input: $input) {
      id
      name
    }
  }
`;

const statusTemplateValidation = (t: (name: string | object) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

interface StatusTemplateCreationProps {
  contextual: boolean;
  inputValueContextual: string;
  creationCallback: (
    data: StatusTemplateCreationContextualMutation$data
  ) => void;
  handleCloseContextual: () => void;
  openContextual: boolean;
  paginationOptions?: StatusTemplatesLinesPaginationQuery$variables;
}

const StatusTemplateCreation: FunctionComponent<StatusTemplateCreationProps> = ({
  contextual,
  inputValueContextual,
  creationCallback,
  handleCloseContextual,
  openContextual,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const onSubmit: FormikConfig<{ name: string; color: string }>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    commitMutation({
      mutation: contextual
        ? statusTemplateContextualMutation
        : statusTemplateMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      updater: (store: RecordSourceSelectorProxy) => {
        if (!contextual) {
          insertNode(
            store,
            'Pagination_statusTemplates',
            paginationOptions,
            'statusTemplateAdd',
          );
        }
      },
      onCompleted: (
        response: StatusTemplateCreationContextualMutation$data,
      ) => {
        setSubmitting(false);
        resetForm();
        if (contextual) {
          creationCallback(response);
          handleCloseContextual();
        }
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
    });
  };

  const onResetContextual = () => handleCloseContextual();

  const renderClassic = () => {
    return (
      <Drawer
        title={t('Create a status template')}
        variant={DrawerVariant.createWithPanel}
      >
        {({ onClose }) => (
          <Formik<{ name: string; color: string }>
            initialValues={{
              name: '',
              color: '',
            }}
            validationSchema={statusTemplateValidation(t)}
            onSubmit={(values, formikHelpers) => {
              onSubmit(values, formikHelpers);
              onClose();
            }}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t('Name')}
                  fullWidth={true}
                />
                <Field
                  component={ColorPickerField}
                  name="color"
                  label={t('Color')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <div className={classes.buttons}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Create')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        )}
      </Drawer>
    );
  };

  const renderContextual = () => {
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            name: inputValueContextual,
            color: '',
          }}
          validationSchema={statusTemplateValidation(t)}
          onSubmit={onSubmit}
          onReset={onResetContextual}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Dialog
                open={openContextual}
                PaperProps={{ elevation: 1 }}
                onClose={handleCloseContextual}
                fullWidth={true}
              >
                <DialogTitle>{t('Create a status template')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialog }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={ColorPickerField}
                    name="color"
                    label={t('Color')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
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

  return contextual ? renderContextual() : renderClassic();
};

export default StatusTemplateCreation;
