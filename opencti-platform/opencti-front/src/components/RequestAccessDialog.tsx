import React from 'react';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import MyOrganizationField from '@components/common/form/MyOrganizationField';
import * as Yup from 'yup';
import { useFormatter } from './i18n';
import TextField from './TextField';
import useApiMutation from '../utils/hooks/useApiMutation';
import Transition from './Transition';
import { RequestAccessDialogMutation$variables } from './__generated__/RequestAccessDialogMutation.graphql';
import { handleErrorInForm } from '../relay/environment';
import useAuth from '../utils/hooks/useAuth';
import { FieldOption, fieldSpacingContainerStyle } from '../utils/field';
import type { Theme } from './Theme';

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
  label: string;
}

interface RequestAccessFormAddInput {
  organizations: OrganizationForm;
  request_access_entities: string[];
  request_access_reason: string;
  request_access_type: 'organization_sharing';
}

const requestAccessValidation = (t: (v: string) => string) => Yup.object().shape({
  organizations: Yup.object().required(t('This field is required')),
});

const RequestAccessDialog: React.FC<RequestAccessDialogProps> = ({ open, onClose, entitiesIds }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { me } = useAuth();
  const meResolvedId = me.id;
  let initialOrganization: FieldOption = { value: '', label: '' };
  if (me?.objectOrganization && me?.objectOrganization?.edges?.length > 0) {
    const organizationData = me?.objectOrganization;
    initialOrganization = {
      label: organizationData?.edges[0].node.name,
      value: organizationData?.edges[0].node.id,
    };
  }

  const [commit] = useApiMutation(requestAccessDialogMutation, undefined, {
    successMessage: `${t_i18n('Your request for access has been successfully taken into account')}`,
  });
  const initialValues: RequestAccessFormAddInput = {
    request_access_reason: '',
    organizations: initialOrganization,
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
        slotProps={{
          paper: { variant: 'elevation', elevation: 1 },
        }}
        keepMounted={true}
        fullWidth={true}
        slots={{ transition: Transition }}
        onClose={onClose}
      >
        <DialogContent>
          <DialogTitle style={{ padding: '16px 0' }}>{t_i18n('Request Access')}</DialogTitle>
          <Formik
            initialValues={initialValues}
            onSubmit={onSubmit}
            validationSchema={requestAccessValidation(t_i18n)}
          >
            {({ isSubmitting, submitForm, setFieldValue }) => {
              return (
                <Form>
                  <DialogContent style={{ padding: theme.spacing(1) }}>
                    <DialogContentText>
                      {t_i18n('Your organization does not have permission...')}
                    </DialogContentText>
                    <Field
                      component={TextField}
                      name="request_access_reason"
                      label={t_i18n('Enter justification for requesting access to this knowledge')}
                      fullWidth={true}
                      variant="standard"
                      style={fieldSpacingContainerStyle}
                      askAi={false}
                      multiline={true}
                      minRows={5}
                    />
                    <MyOrganizationField
                      name="organizations"
                      style={fieldSpacingContainerStyle}
                      label={t_i18n('Select one of your organization for requesting access to this knowledge')}
                      multiple={false}
                      disabled={false}
                      onChange={setFieldValue}
                    />
                  </DialogContent>
                  <DialogActions>
                    <Button variant="secondary" onClick={onClose} disabled={isSubmitting}>
                      {t_i18n('Cancel')}
                    </Button>
                    <Button onClick={submitForm} disabled={isSubmitting}>
                      {t_i18n('Request Access')}
                    </Button>
                  </DialogActions>
                </Form>
              );
            }}
          </Formik>
        </DialogContent>
      </Dialog>
    )}
    </>
  );
};

export default RequestAccessDialog;
