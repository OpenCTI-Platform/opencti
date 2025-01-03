import React from 'react';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import ObjectOrganizationField from '@components/common/form/ObjectOrganizationField';
import { Field, Form, Formik } from 'formik';
import { graphql } from 'react-relay';
import MarkdownField from './fields/MarkdownField';
import { useFormatter } from './i18n';
import useApiMutation from '../utils/hooks/useApiMutation';
import Transition from './Transition';
import { RequestAccessDialogMutation$variables } from './__generated__/RequestAccessDialogMutation.graphql';

const requestAccessDialogMutation = graphql`
  mutation RequestAccessDialogMutation($input: RequestAccessAddInput!) {
    requestAccessAdd(input: $input)
  }
`;

interface RequestAccessDialogProps {
  open: boolean;
  onClose: () => void;
  entitiesIds: string[];
}

const RequestAccessDialog: React.FC<RequestAccessDialogProps> = ({ open, onClose, entitiesIds }) => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    request_access_reason: '',
    organizations: [],
    request_access_entities: '',
    request_access_type: 'organization_sharing',
  };
  const [commit] = useApiMutation(requestAccessDialogMutation, undefined, {
    successMessage: `${t_i18n('Your request for access has been successfully taken into account')}`,
  });
  const onSubmit = (values: any, { setSubmitting }: { setSubmitting: (isSubmitting: boolean) => void }) => {
    const organizations = Array.isArray(values.organizations)
      ? values.organizations.map((org) => org.value)
      : [values.organizations.value];

    const input: RequestAccessDialogMutation$variables['input'] = {
      request_access_reason: values.request_access_reason,
      request_access_entities: [entitiesIds[0]],
      request_access_members: organizations,
      request_access_type: 'organization_sharing',
    };

    commit({
      variables: { input },
      onError: () => setSubmitting(false),
      onCompleted: () => {
        setSubmitting(false);
        onClose();
      },
    });
  };
  return (
    <Dialog
      open={open}
      PaperProps={{ variant: 'elevation', elevation: 1 }}
      keepMounted={true}
      fullWidth={true}
      TransitionComponent={Transition}
      onClose={onClose}
    >
      <DialogContent>
        <DialogTitle style={{ padding: '16px 0' }}>{t_i18n('Request Access for entity')}</DialogTitle>
        <Formik
          initialValues={initialValues}
          onSubmit={onSubmit}
        >
          {({ isSubmitting, submitForm }) => {
            return (
              <Form>
                <DialogContent style={{ padding: 0 }}>
                  <DialogContentText>
                    {t_i18n(
                      'Your account/organization does not have permission to create/update this entity as it already exist in the platform but is under restriction. You can make an access request from the original entity owner below. This will notify the organization that created the entity that you wish to access it.',
                    )}
                  </DialogContentText>
                  <Field
                    component={MarkdownField}
                    name="request_access_reason"
                    label={t_i18n('Enter justification for requesting this entity')}
                    fullWidth={true}
                    multiline={true}
                    rows={4}
                    style={{ marginTop: 20 }}
                    askAi={false}
                  />
                  <ObjectOrganizationField
                    name="organizations"
                    style={{ width: '100%', paddingTop: '16px' }}
                    label={t_i18n('Organization')}
                    multiple={true}
                    alert={false}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={onClose} disabled={isSubmitting}>
                    {t_i18n('Cancel')}
                  </Button>
                  <Button color="secondary" onClick={submitForm} disabled={isSubmitting}>
                    {t_i18n('Request Access')}
                  </Button>
                </DialogActions>
              </Form>
            );
          }}
        </Formik>
      </DialogContent>
    </Dialog>
  );
};

export default RequestAccessDialog;
