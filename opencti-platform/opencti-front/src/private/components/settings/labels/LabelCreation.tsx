import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import DialogActions from '@mui/material/DialogActions';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import ColorPickerField from '../../../../components/ColorPickerField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import { PaginationOptions } from '../../../../components/list_lines';
import SimpleTextField from '../../../../components/SimpleTextField';
import { commitMutation, defaultCommitMutation, handleErrorInForm } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { LabelAddInput, LabelCreationContextualMutation$data } from './__generated__/LabelCreationContextualMutation.graphql';

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
      color
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
  const { t_i18n } = useFormatter();
  const labelValidation = Yup.object().shape({
    value: Yup.string().required(t_i18n('This field is required')),
    color: Yup.string().required(t_i18n('This field is required')),
  });
  const initialValues: LabelAddInput = {
    value: contextual ? inputValueContextual : '',
    color: '',
  };
  const onSubmit: FormikConfig<LabelAddInput>['onSubmit'] = async (values, { setSubmitting, setErrors, resetForm }) => {
    if (dryrun && contextual) {
      creationCallback({ labelAdd: values } as LabelCreationContextualMutation$data);
      handleClose();
      return;
    }
    commitMutation({
      ...defaultCommitMutation,
      mutation: contextual ? labelContextualMutation : labelMutation,
      variables: { input: values },
      updater: contextual ? undefined : (store: RecordSourceSelectorProxy) => {
        insertNode(store, 'Pagination_labels', paginationOptions, 'labelAdd');
      },
      setSubmitting,
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response: LabelCreationContextualMutation$data) => {
        setSubmitting(false);
        resetForm();
        if (contextual) {
          creationCallback(response);
          handleClose();
        }
      },
    });
  };

  const onReset = () => handleClose();

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
          enableReinitialize={true}
          initialValues={initialValues}
          required={required}
          validationSchema={labelValidation}
          onSubmit={onSubmit}
          onReset={onReset}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Dialog
                open={open}
                onClose={handleClose}
                title={t_i18n('Create a label')}
              >
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
