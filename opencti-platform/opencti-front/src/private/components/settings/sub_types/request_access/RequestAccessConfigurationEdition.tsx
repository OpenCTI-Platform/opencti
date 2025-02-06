import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import { Form, Formik } from 'formik';
import StatusTemplateField, { StatusTemplateFieldData } from '@components/common/form/StatusTemplateField';
import Button from '@mui/material/Button';
import ObjectMembersField from '@components/common/form/ObjectMembersField';
import { FormikConfig } from 'formik/dist/types';
import {
  RequestAccessConfigurationEditionMutation,
  RequestAccessConfigureInput,
} from '@components/settings/sub_types/__generated__/RequestAccessConfigurationEditionMutation.graphql';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../../relay/environment';

const requestAccessConfigurationMutation = graphql`
    mutation RequestAccessConfigurationEditionMutation($input: RequestAccessConfigureInput!) {
        requestAccessConfigure(input: $input) {
            id
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
    requestAccessApprovedStatus {
        id
        template {
            id
            color
            name
        }
    }
    requestAccessDeclinedStatus {
        id
        template {
            id
            color
            name
        }
    }
    request_access_workflow {
        approval_admin
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
  approvalAdmin: string[]
}

const RequestAccessConfigurationEdition: FunctionComponent<RequestAccessWorkflowProps> = ({
  handleClose,
  open,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const queryData = useFragment(requestAccessConfigurationFragment, queryRef);
  console.log('RA Edit => queryData:', queryData);
  const initialValues: RequestAccessEditionFormInputs = {
    acceptedTemplate: {
      color: queryData?.requestAccessApprovedStatus?.template?.color || '#fff',
      label: queryData?.requestAccessApprovedStatus?.template?.name || '-',
      value: queryData?.requestAccessApprovedStatus?.template?.id || '-',
    },
    declinedTemplate: {
      color: queryData?.requestAccessDeclinedStatus?.template?.color || '#fff',
      label: queryData?.requestAccessDeclinedStatus?.template?.name || '-',
      value: queryData?.requestAccessDeclinedStatus?.template?.id || '-',
    },
    approvalAdmin: [],
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
    console.log('RA Edit => onSubmit:', values);

    const input: RequestAccessConfigureInput = {
      approve_status_template_id: values.acceptedTemplate.value || '', // FIXME remove || ''
      decline_status_template_id: values.declinedTemplate.value || '', // FIXME remove || ''
      approval_admin: values.approvalAdmin,
    };
    commit({
      variables: {
        input,
      },
      updater: (/* store, response */) => {
        /* if (updater && response) {
          updater(store, 'caseRftAdd', response.caseRftAdd);
        } */
        console.log('updater');
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (/* response */) => {
        console.log('onCompleted');
        setSubmitting(false);
        resetForm();
        handleClose();
        /*
        if (onClose) {
          onClose();
        }
        if (mapAfter) {
          navigate(
            `/dashboard/cases/rfts/${response.caseRftAdd?.id}/content/mapping`,
          );
        } */
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
              />
              <StatusTemplateField
                name="declinedTemplate"
                setFieldValue={setFieldValue}
                helpertext={'Request for information status to use when access request is declined.'}
                required={true}
              />
              <ObjectMembersField
                name="validors"
                label="Select authorized members"
                onChange={setFieldValue}
                required={true}
                multiple={true}
              />
              <Button
                color="primary"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('GO go go')}
              </Button>
            </Form>
          );
        }}
      </Formik>
    </Drawer>
  );
};

export default RequestAccessConfigurationEdition;
