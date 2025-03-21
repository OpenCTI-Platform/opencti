import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
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
import { Option } from '@components/common/form/ReferenceField';
import { FormikHelpers } from 'formik/dist/types';
import { ConnectorsStatus_data$data } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';

const registerManagedConnectorMutation = graphql`
  mutation ManagedConnectorCreationMutation($input: AddManagedConnectorInput) {
    managedConnectorAdd(input: $input) {
      id
      manager_id
      manager_contract_image
      manager_contract_hash
      manager_requested_status
      manager_current_status
      manager_contract_configuration {
        key
        value
      }
    }
  }
`;

interface ManagedConnectorValues {
  name: string
  contract?: number
  creator?: Option
  contractValues: Record<string, string | boolean>
}

const ManagedConnectorCreation = ({
  manager,
  onClose,
}: {
  manager: ConnectorsStatus_data$data['connectorManagers'][0]
  onClose: () => void
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const contracts = manager.connector_manager_contracts.map((contract) => JSON.parse(contract));
  const contractNames = contracts.map((contract) => contract.title);

  const formRef = createRef<CoreForm>();

  const [commitRegister] = useApiMutation(registerManagedConnectorMutation);
  const submitConnectorManagementCreation = (values: ManagedConnectorValues, {
    setSubmitting,
    resetForm,
  }: Partial<FormikHelpers<ManagedConnectorValues>>) => {
    if (values.contract == null) {
      return;
    }
    const contract = contracts[values.contract];
    const input = {
      name: values.name,
      manager_id: manager.id,
      connector_user_id: values.creator?.value,
      manager_contract_image: contract.container_image,
      manager_contract_configuration: Object.entries(values.contractValues).map(([key, value]) => ({ key, value: value.toString() })),
    };
    commitRegister({
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
  return (
    <Drawer
      title={t_i18n('Create a connector')}
      open={!!manager}
      onClose={onClose}
    >
      <Formik<ManagedConnectorValues>
        onReset={onClose}
        validationSchema={Yup.object().shape({
          name: Yup.string().required().min(2),
          creator: Yup.object().required(),
          contract: Yup.number().required(),
          contractValues: Yup.object().required(),
        })}
        initialValues={{
          contractValues: {},
          contract: undefined,
          creator: undefined,
          name: '',
        }}
        onSubmit={() => {
        }}
      >
        {({ values, setFieldValue, isSubmitting, setSubmitting, resetForm, isValid }) => {
          return (
            <Form>
              <Field
                component={SelectField}
                variant="standard"
                name="contract"
                label={t_i18n('Type')}
                fullWidth={true}
                multiple={false}
                required
                containerstyle={{ width: '100%', marginTop: 20 }}
              >
                {contractNames.map((name: string, index: number) => (
                  <MenuItem key={name} value={index}>
                    {name}
                  </MenuItem>
                ))}
              </Field>
              {values.contract && (
                <>
                  <Field
                    component={TextField}
                    style={fieldSpacingContainerStyle}
                    variant="standard"
                    name="name"
                    label={t_i18n('Name')}
                    required
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
                    schema={contracts[values.contract]}
                    validator={validator}
                    onChange={(newValue) => setFieldValue('contractValues', newValue.formData)}
                  />
                </>
              )}
              <div style={{ float: 'right', marginTop: theme.spacing(2), gap: theme.spacing(1), display: 'flex' }}>
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
                  disabled={!values.contract || !isValid || isSubmitting}
                >
                  {t_i18n('Submit')}
                </Button>
              </div>
            </Form>
          );
        }}
      </Formik>
    </Drawer>
  );
};

export default ManagedConnectorCreation;
