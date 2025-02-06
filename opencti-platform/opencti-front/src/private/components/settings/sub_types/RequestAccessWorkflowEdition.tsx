import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import { Field, Form, Formik } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';

export const requestAccessWorkflowEditionQuery = graphql`
  query RequestAccessWorkflowEditionQuery($id: String!) {
    entitySetting(id: $id) {
      ...RequestAccessStatusFragment_entitySetting
    }
  }
`;

const requestAccessWorkflowFragment = graphql`
  fragment RequestAccessWorkflow_entitySettings on EntitySetting {
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
}

interface RequestAccessEditionFormData {
  name: string
}

const RequestAccessWorkflowEdition: FunctionComponent<RequestAccessWorkflowProps> = ({
}) => {
  const { t_i18n } = useFormatter();

  const onSubmit = (value: any) => {
    console.log('onSubmit', value);
  };

  const handleClose = (value: any) => {
    console.log('handleClose', value);
  };

  const initialValues: RequestAccessEditionFormData = {
    name: 'coucou',
  };

  return (
    <Drawer
      open={open}
      title={t_i18n('Request Access Configuration')}
      onClose={handleClose}
    >
      <Formik<RequestAccessEditionFormData>
        enableReinitialize={true}
        initialValues={initialValues}
        onSubmit={onSubmit}
      >
        {({ values }) => (
          <Form>
            <Field
              component={TextField}
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
            />
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default RequestAccessWorkflowEdition;
