import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import { FormikConfig } from 'formik/dist/types';
import StatusTemplateFieldScoped from '@components/settings/sub_types/workflow/StatusTemplateFieldScoped';
import GroupField, { GroupFieldOption } from '@components/common/form/GroupField';
import { Option } from '@components/common/form/ReferenceField';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { RequestAccessConfigurationEdition_requestAccess$key } from './__generated__/RequestAccessConfigurationEdition_requestAccess.graphql';
import { RequestAccessConfigurationEditionMutation, RequestAccessConfigureInput } from './__generated__/RequestAccessConfigurationEditionMutation.graphql';

const requestAccessConfigurationMutation = graphql`
    mutation RequestAccessConfigurationEditionMutation($input: RequestAccessConfigureInput!) {
        requestAccessConfigure(input: $input) {
            ...RequestAccessStatusFragment_requestAccess
        }
    }
`;

export const requestAccessConfigurationFragment = graphql`
  fragment RequestAccessConfigurationEdition_requestAccess on RequestAccessConfiguration {
    id
    approved_status {
      id
      template {
        id
        color
        name
      }
    }
    declined_status {
      id
      template {
        id
        color
        name
      }
    }
    approval_admin {
      id
      name
    }
  }
`;

interface RequestAccessWorkflowProps {
  handleClose: () => void;
  data: RequestAccessConfigurationEdition_requestAccess$key
  open?: boolean
}

interface RequestAccessEditionFormInputs {
  acceptedTemplate: Option
  declinedTemplate: Option
  approvalAdmin: GroupFieldOption
}

const RequestAccessConfigurationEdition: FunctionComponent<RequestAccessWorkflowProps> = ({
  handleClose,
  open,
  data,
}) => {
  const { t_i18n } = useFormatter();
  const requestAccessData = useFragment(requestAccessConfigurationFragment, data);
  const approvedTemplateStatus = requestAccessData.approved_status?.template;
  const declinedTemplateStatus = requestAccessData.declined_status?.template;
  const adminData = requestAccessData.approval_admin;
  const initialValues: RequestAccessEditionFormInputs = {
    acceptedTemplate: {
      color: approvedTemplateStatus ? approvedTemplateStatus.color : '#fff',
      label: approvedTemplateStatus ? approvedTemplateStatus.name : '-',
      value: approvedTemplateStatus ? approvedTemplateStatus.id : '-',
    },
    declinedTemplate: {
      color: declinedTemplateStatus ? declinedTemplateStatus.color : '#fff',
      label: declinedTemplateStatus ? declinedTemplateStatus.name : '-',
      value: declinedTemplateStatus ? declinedTemplateStatus.id : '-',
    },
    approvalAdmin: {
      label: adminData && adminData[0] ? adminData[0].name : '',
      value: adminData && adminData[0] ? adminData[0].id : '',
    },
  };

  const [commit] = useApiMutation<RequestAccessConfigurationEditionMutation>(
    requestAccessConfigurationMutation,
    undefined,
    { successMessage: `${t_i18n('Request access configuration successfully updated')}` },
  );

  const onSubmit: FormikConfig<RequestAccessEditionFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: RequestAccessConfigureInput = {
      approved_status_id: values.acceptedTemplate.value,
      declined_status_id: values.declinedTemplate.value,
      approval_admin: [values.approvalAdmin.value],
    };
    commit({
      variables: {
        input,
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  return (
    <Drawer
      open={open}
      title={t_i18n('Request Access Configuration')}
      onClose={handleClose}
    >
      <Formik<RequestAccessEditionFormInputs>
        enableReinitialize={true}
        initialValues={initialValues}
        onSubmit={onSubmit}
        validateOnChange={true}
        validateOnBlur={true}
      >
        {({ submitForm, isSubmitting, setFieldValue }) => {
          return (
            <Form>
              <StatusTemplateFieldScoped
                name="acceptedTemplate"
                label={t_i18n('On approval move to status:')}
                setFieldValue={setFieldValue}
                helpertext={t_i18n('Request for information status to use when access request is accepted.')}
                required={true}
                style={fieldSpacingContainerStyle}
                scope='REQUEST_ACCESS'
              />
              <StatusTemplateFieldScoped
                name="declinedTemplate"
                label={t_i18n('On decline move to status:')}
                setFieldValue={setFieldValue}
                helpertext={t_i18n('Request for information status to use when access request is declined.')}
                required={true}
                style={fieldSpacingContainerStyle}
                scope='REQUEST_ACCESS'
              />
              <GroupField
                name="approvalAdmin"
                label={t_i18n('Validator group membership:')}
                onChange={setFieldValue}
                multiple={false}
                style={fieldSpacingContainerStyle}
              />
              <Button
                variant="contained"
                color="primary"
                onClick={submitForm}
                disabled={isSubmitting}
                style={{ marginTop: 20, float: 'right' }}
              >
                {t_i18n('Update')}
              </Button>
            </Form>
          );
        }}
      </Formik>
    </Drawer>
  );
};

export default RequestAccessConfigurationEdition;
