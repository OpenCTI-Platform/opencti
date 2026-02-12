import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import DialogActions from '@mui/material/DialogActions';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import ColorPickerField from '../../../../components/ColorPickerField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { commitMutation, defaultCommitMutation, handleErrorInForm } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import { StatusTemplateAddInput, StatusTemplateCreationContextualMutation$data } from './__generated__/StatusTemplateCreationContextualMutation.graphql';
import { StatusTemplatesLinesPaginationQuery$variables } from './__generated__/StatusTemplatesLinesPaginationQuery.graphql';

const statusTemplateMutation = graphql`
  mutation StatusTemplateCreationMutation($input: StatusTemplateAddInput!) {
    statusTemplateAdd(input: $input) {
      ...StatusTemplatesLine_node
    }
  }
`;

const statusTemplateContextualMutation = graphql`
  mutation StatusTemplateCreationContextualMutation( $input: StatusTemplateAddInput!) {
    statusTemplateAdd(input: $input) {
      id
      name
    }
  }
`;

const CreateStatusTemplateControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType="StatusTemplate"
    {...props}
  />
);

interface StatusTemplateCreationProps {
  contextual: boolean;
  inputValueContextual: string;
  creationCallback: (
    data: StatusTemplateCreationContextualMutation$data,
  ) => void;
  handleClose: () => void;
  open: boolean;
  paginationOptions?: StatusTemplatesLinesPaginationQuery$variables;
}

const StatusTemplateCreation: FunctionComponent<StatusTemplateCreationProps> = ({
  contextual,
  inputValueContextual,
  creationCallback,
  handleClose,
  open,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const statusTemplateValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    color: Yup.string().required(t_i18n('This field is required')),
  });
  const initialValues = {
    name: '',
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
        ? statusTemplateContextualMutation
        : statusTemplateMutation,
      variables: { input: finalValues },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_statusTemplates',
          paginationOptions,
          'statusTemplateAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const onSubmitContextual: FormikConfig<StatusTemplateAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const finalValues = {
      ...values,
    };
    commitMutation({
      ...defaultCommitMutation,
      mutation: statusTemplateContextualMutation,
      variables: { input: finalValues },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (
        response: StatusTemplateCreationContextualMutation$data,
      ) => {
        setSubmitting(false);
        resetForm();
        if (contextual) {
          creationCallback(response);
          handleClose();
        }
      },
    });
  };

  const onResetContextual = () => handleClose();

  const renderClassic = () => {
    return (
      <Drawer
        title={t_i18n('Create a status template')}
        controlledDial={CreateStatusTemplateControlledDial}
      >
        {({ onClose }) => (
          <Formik
            initialValues={initialValues}
            validationSchema={statusTemplateValidation}
            onSubmit={onSubmit}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Field
                  component={ColorPickerField}
                  name="color"
                  label={t_i18n('Color')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <FormButtonContainer>
                  <Button
                    variant="secondary"
                    onClick={handleReset}
                    disabled={isSubmitting}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t_i18n('Create')}
                  </Button>
                </FormButtonContainer>
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
          initialValues={{
            name: inputValueContextual,
            color: '',
          }}
          validationSchema={statusTemplateValidation}
          onSubmit={onSubmitContextual}
          onReset={onResetContextual}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Dialog
                open={open}
                onClose={handleClose}
                title={t_i18n('Create a status template')}
              >
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Field
                  component={ColorPickerField}
                  name="color"
                  label={t_i18n('Color')}
                  fullWidth={true}
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

  return contextual ? renderContextual() : renderClassic();
};

export default StatusTemplateCreation;
