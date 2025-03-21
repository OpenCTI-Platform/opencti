import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import CreatorField from '@components/common/form/CreatorField';
import JsonForm from '@rjsf/mui';
import { uiSchema } from '@components/settings/notifiers/NotifierUtils';
import validator from '@rjsf/validator-ajv8';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import React, { createRef } from 'react';
import { useTheme } from '@mui/styles';
import { graphql } from 'react-relay';
import CoreForm from '@rjsf/core';
import { FormikHelpers } from 'formik/dist/types';
import { Option } from '@components/common/form/ReferenceField';
import { ConnectorsStatus_data$data } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useComputeConnectorStatus } from '../../../../utils/Connector';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';

const updateRequestedStatus = graphql`
  mutation ManagedConnectorEditionUpdateStatusMutation($input: RequestConnectorStatusInput!) {
    updateConnectorRequestedStatus(input: $input) {
      id
      manager_current_status
      manager_requested_status
    }
  }
`;

const updateManagedConnector = graphql`
  mutation ManagedConnectorEditionMutation($input: EditManagedConnectorInput) {
    managedConnectorEdit(input: $input){
      id
      manager_requested_status
      manager_current_status
      manager_contract_configuration {
        key
        value
      }
    }
  }
`;

const deleteManagedConnector = graphql`
  mutation ManagedConnectorEditionDeleteMutation($id: ID!){
    deleteConnector(id: $id)
  }
`;

interface ManagedConnectorValues {
  name: string
  creator?: Option
  contractValues: Record<string, string | boolean>
}

const ManagedConnectorEdition = ({
  manager,
  connector,
  onClose,
}: {
  manager: ConnectorsStatus_data$data['connectorManagers'][0]
  connector: ConnectorsStatus_data$data['connectors'][0]
  onClose: () => void
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const contracts = manager.connector_manager_contracts.map((contract) => JSON.parse(contract));
  const contract = contracts.find(({ container_image }) => container_image === connector.manager_contract_image);
  contract.default = {};
  (connector.manager_contract_configuration as { key: string, value: string }[]).forEach(({ key, value }) => {
    if (['true', 'false'].includes(value)) {
      contract.default[key] = value === 'true';
    } else {
      contract.default[key] = value;
    }
  });

  const formRef = createRef<CoreForm>();

  const [commitUpdateStatus] = useApiMutation(updateRequestedStatus);
  const [commitUpdate] = useApiMutation(updateManagedConnector);
  const [commitDelete] = useApiMutation(deleteManagedConnector);
  const submitConnectorManagementCreation = (values: ManagedConnectorValues, {
    setSubmitting,
    resetForm,
  }: Partial<FormikHelpers<ManagedConnectorValues>>) => {
    const input = {
      id: connector.id,
      name: values.name,
      connector_user_id: values.creator?.value,
      manager_contract_configuration: Object.entries(values.contractValues).map(([key, value]) => ({ key, value: value.toString() })),
    };
    commitUpdate({
      variables: {
        input,
      },
      onError: () => setSubmitting?.(false),
      onCompleted: () => {
        setSubmitting?.(false);
        resetForm?.();
        onClose();
      },
    });
  };

  const computeConnectorStatus = useComputeConnectorStatus();
  return (
    <Drawer
      title={(
        <div style={{ display: 'flex', gap: theme.spacing(1) }}>
          {t_i18n('Update a connector')}
          {computeConnectorStatus(connector)}
        </div>
      )}
      open={!!manager}
      onClose={onClose}
      header={(
        <div style={{ display: 'flex', flex: 1, justifyContent: 'end', marginRight: theme.spacing(2) }}>
          <Button
            variant="outlined"
            size="small"
            color={connector.manager_current_status === 'started' ? 'error' : 'primary'}
            onClick={() => commitUpdateStatus({
              variables: {
                input: {
                  id: connector.id,
                  status: connector.manager_current_status === 'started' ? 'stopping' : 'starting',
                },
              },
              onCompleted: onClose,
            })}
          >{t_i18n(connector.manager_current_status === 'started' ? 'Stop' : 'Start')}</Button>
        </div>
      )}
    >
      <Formik<ManagedConnectorValues>
        onReset={onClose}
        validationSchema={Yup.object().shape({
          name: Yup.string().required().min(2),
          creator: Yup.object().required(),
          contractValues: Yup.object().required(),
        })}
        initialValues={{
          contractValues: {},
          creator: connector.connector_user ? { value: connector.connector_user.id, label: connector.connector_user.name } : undefined,
          name: connector.name,
        }}
        onSubmit={() => {
        }}
      >
        {({ values, setFieldValue, isSubmitting, setSubmitting, resetForm, isValid }) => {
          return (
            <Form>
              <Field
                component={TextField}
                style={fieldSpacingContainerStyle}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                required
                disabled
                fullWidth={true}
              />
              <CreatorField
                label={'Connector user'}
                containerStyle={fieldSpacingContainerStyle}
                onChange={setFieldValue}
                name="creator"
                required
              />
              <JsonForm
                uiSchema={{
                  ...uiSchema,
                  'ui:description': '',
                  'ui:title': '',
                }}
                showErrorList={false}
                liveValidate
                ref={formRef}
                schema={contract}
                validator={validator}
                onChange={(newValue) => setFieldValue('contractValues', newValue.formData)}
              />
              <div style={{ marginTop: theme.spacing(2), gap: theme.spacing(1), display: 'flex', justifyContent: 'space-between' }}>
                <Button
                  variant="outlined"
                  color="error"
                  onClick={() => {
                    commitDelete({ variables: { id: connector.id }, onCompleted: onClose });
                  }}
                >
                  {t_i18n('Delete')}
                </Button>
                <div style={{ display: 'flex', gap: theme.spacing(1) }}>
                  <Button
                    variant="outlined"
                    color="primary"
                    onClick={() => {
                      resetForm();
                    }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={() => {
                      if (formRef.current?.validateForm()) {
                        submitConnectorManagementCreation(values, {
                          setSubmitting,
                          resetForm,
                        });
                      }
                    }}
                    disabled={!isValid || isSubmitting}
                  >
                    {t_i18n('Update')}
                  </Button>
                </div>
              </div>
            </Form>
          );
        }}
      </Formik>
    </Drawer>
  );
};

export default ManagedConnectorEdition;
