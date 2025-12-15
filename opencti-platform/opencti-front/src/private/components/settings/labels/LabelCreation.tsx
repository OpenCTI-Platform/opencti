import React, { FunctionComponent } from 'react';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useTheme } from '@mui/styles';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import makeStyles from '@mui/styles/makeStyles';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import SimpleTextField from '../../../../components/SimpleTextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { commitMutation, defaultCommitMutation, handleErrorInForm } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import type { Theme } from '../../../../components/Theme';
import { PaginationOptions } from '../../../../components/list_lines';
import { LabelAddInput, LabelCreationContextualMutation$data } from './__generated__/LabelCreationContextualMutation.graphql';

const useStyles = makeStyles<Theme>(() => ({
  dialog: {
    overflow: 'hidden',
  },
}));

const labelMutation = graphql`
  mutation LabelCreationMutation($input: LabelAddInput!) {
    labelAdd(input: $input) {
      ...LabelsLine_node
    }
  }
`;

const labelContextualMutation = graphql`
  mutation LabelCreationContextualMutation($input: LabelAddInput!) {
    labelAdd(input: $input) {
      id
      value
    }
  }
`;

const CreateLabelsControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType="Label"
    {...props}
  />
);

interface LabelCreationProps {
  contextual: boolean;
  inputValueContextual: string;
  required: boolean;
  creationCallback: (
    data: LabelCreationContextualMutation$data,
  ) => void;
  handleClose: () => void;
  open: boolean;
  paginationOptions?: PaginationOptions;
  dryrun: boolean;
}

const LabelCreation: FunctionComponent<LabelCreationProps> = ({
  contextual,
  inputValueContextual,
  required,
  creationCallback,
  handleClose,
  open,
  paginationOptions,
  dryrun,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const labelValidation = Yup.object().shape({
    value: Yup.string().required(t_i18n('This field is required')),
    color: Yup.string().required(t_i18n('This field is required')),
  });
  const initialValues: LabelAddInput = {
    value: contextual ? inputValueContextual : '',
    color: '',
  };
  const onSubmit = (
    values: typeof initialValues,
    { setSubmitting, resetForm }: {
      setSubmitting: (flag: boolean) => void;
      resetForm: () => void;
    },
  ) => {
    const finalValues = {
      ...values,
    };
    commitMutation({
      ...defaultCommitMutation,
      mutation: contextual
        ? labelContextualMutation
        : labelMutation,
      variables: { input: finalValues },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_labels',
          paginationOptions,
          'labelAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const onSubmitContextual: FormikConfig<LabelAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const finalValues = {
      ...values,
    };
    if (dryrun && contextual) {
      creationCallback({
        labelAdd: values,
      } as LabelCreationContextualMutation$data);
      handleClose();
      return;
    }
    commitMutation({
      ...defaultCommitMutation,
      mutation: labelContextualMutation,
      variables: { input: finalValues },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (
        response: LabelCreationContextualMutation$data,
      ) => {
        setSubmitting(false);
        resetForm();
        creationCallback(response);
        handleClose();
      },
    });
  };

  const onResetContextual = () => handleClose();

  const renderClassic = () => {
    return (
      <Drawer
        title={t_i18n('Create a label')}
        controlledDial={CreateLabelsControlledDial}
      >
        {({ onClose }) => (
          <Formik
            initialValues={initialValues}
            validationSchema={labelValidation}
            onSubmit={onSubmit}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={SimpleTextField}
                  variant="standard"
                  name="value"
                  label={t_i18n('Value')}
                  fullWidth={true}
                />
                <Field
                  component={ColorPickerField}
                  name="color"
                  label={t_i18n('Color')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <div style={{
                  marginTop: 20,
                  textAlign: 'right',
                }}
                >
                  <Button
                    variant="secondary"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    style={{ marginLeft: theme.spacing(2) }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    disabled={isSubmitting}
                    style={{ marginLeft: theme.spacing(2) }}
                  >
                    {t_i18n('Create')}
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
          initialValues={initialValues}
          required={required}
          validationSchema={labelValidation}
          onSubmit={onSubmitContextual}
          onReset={onResetContextual}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Dialog
                open={open}
                PaperProps={{ elevation: 1 }}
                onClose={handleClose}
                fullWidth={true}
              >
                <DialogTitle>{t_i18n('Create a label')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialog }}>
                  <Field
                    component={SimpleTextField}
                    variant="standard"
                    name="value"
                    label={t_i18n('Value')}
                    fullWidth={true}
                  />
                  <Field
                    component={ColorPickerField}
                    name="color"
                    label={t_i18n('Color')}
                    fullWidth={true}
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

  return contextual ? renderContextual() : renderClassic();
};

export default LabelCreation;
