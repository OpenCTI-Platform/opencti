import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { Form, Formik } from 'formik';
import StatusTemplateField, { StatusTemplateFieldData } from '@components/common/form/StatusTemplateField';
import Button from '@mui/material/Button';
import ObjectMembersField, { OptionMember } from '@components/common/form/ObjectMembersField';
import { FormikConfig } from 'formik/dist/types';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/request_access/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import {
  RequestAccessConfigurationEditionMutation,
  RequestAccessConfigureInput,
} from '@components/settings/sub_types/request_access/__generated__/RequestAccessConfigurationEditionMutation.graphql';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';

const requestAccessConfigurationMutation = graphql`
    mutation RequestAccessConfigurationEditionMutation($input: RequestAccessConfigureInput!) {
        requestAccessConfigure(input: $input) {
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
                type
                name
            }
        }
    }
`;

export const requestAccessConfigurationEditionQuery = graphql`
    query RequestAccessConfigurationEditionQuery($id: String!) {
        entitySetting(id: $id) {
            ...RequestAccessStatusFragment_entitySetting
        }
    }
`;

export const requestAccessConfigurationFragment = graphql`
  fragment RequestAccessConfigurationEdition_entitySettings on EntitySetting {
    id
    requestAccessConfiguration {
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
            type
            name
        }
    }
  }
`;

interface RequestAccessWorkflowProps {
  handleClose: () => void;
  queryRef: RequestAccessStatusFragment_entitySetting$key
  open?: boolean
}

interface RequestAccessEditionFormInputs {
  acceptedTemplate: StatusTemplateFieldData
  declinedTemplate: StatusTemplateFieldData
  approvalAdmin: OptionMember[]
}

const RequestAccessConfigurationEdition: FunctionComponent<RequestAccessWorkflowProps> = ({
  handleClose,
  open,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const queryData = useFragment(requestAccessConfigurationFragment, queryRef);
  const adminData = queryData?.requestAccessConfiguration?.approval_admin;

  const admins :OptionMember[] = [];
  if (adminData) {
    for (let i = 0; i < adminData.length; i += 1) {
      const currentAdmin = adminData[i];
      if (currentAdmin) {
        admins.push(
          {
            label: currentAdmin.name || '-',
            value: currentAdmin.id || '-',
            type: currentAdmin.type || '',
          },
        );
      }
    }
  }
  const approvedTemplateStatus = queryData?.requestAccessConfiguration?.approved_status?.template;
  const declinedTemplateStatus = queryData?.requestAccessConfiguration?.declined_status?.template;
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
    approvalAdmin: admins,
  };

  const [commit] = useApiMutation<RequestAccessConfigurationEditionMutation>(
    requestAccessConfigurationMutation,
    undefined,
    { successMessage: `Request access configuration ${t_i18n('successfully updated')}` },
  );

  const onSubmit: FormikConfig<RequestAccessEditionFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: RequestAccessConfigureInput = {
      approve_status_template_id: values.acceptedTemplate.value || '', // FIXME remove || ''
      decline_status_template_id: values.declinedTemplate.value || '', // FIXME remove || ''
      approval_admin: values.approvalAdmin.map((memberOption) => memberOption.value),
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
              <StatusTemplateField
                name="acceptedTemplate"
                setFieldValue={setFieldValue}
                helpertext={'Request for information status to use when access request is accepted.'}
                required={true}
                style={fieldSpacingContainerStyle}
              />
              <StatusTemplateField
                name="declinedTemplate"
                setFieldValue={setFieldValue}
                helpertext={'Request for information status to use when access request is declined.'}
                required={true}
                style={fieldSpacingContainerStyle}
              />
              <ObjectMembersField
                name="approvalAdmin"
                label={t_i18n('Select authorized members')}
                onChange={setFieldValue}
                required={true}
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
