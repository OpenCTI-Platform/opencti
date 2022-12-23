import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import * as Yup from 'yup';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { statusCreationStatusTemplatesQuery } from './StatusCreation';
import StatusTemplateField from '../../common/form/StatusTemplateField';
import { StatusEdition_status$key } from './__generated__/StatusEdition_status.graphql';
import { StatusCreationStatusTemplatesQuery$data } from './__generated__/StatusCreationStatusTemplatesQuery.graphql';

const statusMutationFieldPatch = graphql`
  mutation StatusEditionFieldPatchMutation(
    $id: ID!
    $statusId: String!
    $input: [EditInput]!
  ) {
    subTypeEdit(id: $id) {
      statusFieldPatch(statusId: $statusId, input: $input) {
        ...SubTypeEdition_subType
      }
    }
  }
`;

const statusValidation = (t: (name: string | object) => string) => Yup.object().shape({
  template: Yup.object().required(t('This field is required')),
  order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

export const StatusEditionFragment = graphql`
  fragment StatusEdition_status on Status {
    id
    order
    template {
      id
      name
      color
    }
  }
`;

interface StatusEditionProps {
  subTypeId: string;
  handleClose: () => void;
  open: boolean;
  status: StatusEdition_status$key;
}

const StatusEdition: FunctionComponent<StatusEditionProps> = ({
  subTypeId,
  handleClose,
  open,
  status,
}) => {
  const { t } = useFormatter();

  const data = useFragment(StatusEditionFragment, status);

  const initialValues = {
    template: data.template
      ? {
        label: data.template.name,
        value: data.template.id,
        color: data.template.color,
      }
      : null,
    order: data.order,
  };

  const handleSubmitStatusTemplate: FormikConfig<{
    template: { label: string; value: string; color: string } | null;
    order: number;
  }>['onSubmit'] = (values, { setSubmitting }) => {
    commitMutation({
      mutation: statusMutationFieldPatch,
      variables: {
        id: subTypeId,
        statusId: data.id,
        input: [
          { key: 'template_id', value: values.template?.value || '' },
          { key: 'order', value: String(values.order) || '' },
        ],
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
    });
  };

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={statusValidation(t)}
      onSubmit={handleSubmitStatusTemplate}
    >
      {({ submitForm, isSubmitting, setFieldValue }) => (
        <Form>
          <Dialog
            open={open}
            PaperProps={{ elevation: 1 }}
            onClose={submitForm}
            fullWidth={true}
          >
            <DialogTitle>{t('Create a status')}</DialogTitle>
            <DialogContent>
              <QueryRenderer
                query={statusCreationStatusTemplatesQuery}
                render={({
                  props,
                }: {
                  props: StatusCreationStatusTemplatesQuery$data;
                }) => {
                  if (props && props.statusTemplates) {
                    return (
                      <StatusTemplateField
                        name="template"
                        setFieldValue={setFieldValue}
                        helpertext={''}
                      />
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
              <DialogActions>
                <Button onClick={submitForm} disabled={isSubmitting}>
                  {t('Close')}
                </Button>
              </DialogActions>
            </DialogContent>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default StatusEdition;
