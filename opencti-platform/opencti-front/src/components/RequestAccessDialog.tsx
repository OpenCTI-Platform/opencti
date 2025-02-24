import React from 'react';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import ObjectOrganizationField from '@components/common/form/ObjectOrganizationField';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { graphql } from 'react-relay';
import { useFormatter } from './i18n';
import TextField from './TextField';
import useApiMutation from '../utils/hooks/useApiMutation';
import Transition from './Transition';
import { RequestAccessDialogMutation$variables } from './__generated__/RequestAccessDialogMutation.graphql';
import { handleErrorInForm } from '../relay/environment';
import useAuth from '../utils/hooks/useAuth';
import { fieldSpacingContainerStyle } from '../utils/field';

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

interface OrganizationForm {
  value: string;
  label: string
}

interface RequestAccessFormAddInput {
  organizations: OrganizationForm;
  request_access_entities: string[];
  request_access_reason: string;
  request_access_type: 'organization_sharing';
}

const RequestAccessDialog: React.FC<RequestAccessDialogProps> = ({ open, onClose, entitiesIds }) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const meResolvedId = me.id;

  const [commit] = useApiMutation(requestAccessDialogMutation, undefined, {
    successMessage: `${t_i18n('Your request for access has been successfully taken into account')}`,
  });
  const initialValues: RequestAccessFormAddInput = {
    request_access_reason: '',
    organizations: { label: '', value: '' },
    request_access_entities: [],
    request_access_type: 'organization_sharing',
  };
  const onSubmit: FormikConfig<RequestAccessFormAddInput>['onSubmit'] = (values, { setSubmitting, resetForm, setErrors }) => {
    const { organizations } = values;

    const input: RequestAccessDialogMutation$variables['input'] = {
      request_access_reason: values.request_access_reason,
      request_access_entities: entitiesIds,
      request_access_members: [organizations.value],
      request_access_type: 'organization_sharing',
    };
    commit({
      variables: { input },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        onClose();
      },
    });
  };

  return (
    <> {meResolvedId && (
      <Dialog
        open={open}
        PaperProps={{ variant: 'elevation', elevation: 1 }}
        keepMounted={true}
        fullWidth={true}
        TransitionComponent={Transition}
        onClose={onClose}
      >
        <DialogContent>
          <DialogTitle style={{ padding: '16px 0' }}>{t_i18n('Request Access')}</DialogTitle>
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
                        'Your account/organization does not have permission to create/update the entity as it already exist in the platform but is under restriction. You can make an access request from the original entity owner below. This will notify the organization that created the entity that you wish to access it.',
                      )}
                    </DialogContentText>
                    <Field
                      component={TextField}
                      name="request_access_reason"
                      label={t_i18n('Enter justification for requesting this entity')}
                      fullWidth={true}
                      variant="standard"
                      style={fieldSpacingContainerStyle}
                      askAi={true}
                      multiline={true}
                      minRows={5}
                    />
                    <ObjectOrganizationField
                      name="organizations"
                      style={fieldSpacingContainerStyle}
                      label={t_i18n('Select the organization of your choice for requesting this entity')}
                      multiple={false}
                      alert={false}
                      filters={{
                        mode: 'and',
                        filters: [
                          { key: 'entity_type', values: ['Organization'], mode: 'or', operator: 'eq' },
                          {
                            key: 'regardingOf',
                            values: [
                              { key: 'id', values: [meResolvedId], mode: 'and', operator: 'eq' },
                              { key: 'relationship_type', values: ['participate-to'], mode: 'and', operator: 'eq' },
                            ],
                          },
                        ],
                        filterGroups: [],
                      }}
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
      </Dialog>)}
    </>
  );
};

export default RequestAccessDialog;
