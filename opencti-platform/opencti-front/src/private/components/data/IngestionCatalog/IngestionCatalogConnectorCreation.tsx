import { Field, Form, Formik } from 'formik';
import TextField from '../../../../components/TextField';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { IngestionConnector } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import { FormikHelpers } from 'formik/dist/types';
import * as Yup from 'yup';
import CreatorField from '@components/common/form/CreatorField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { graphql } from 'react-relay';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { materialRenderers } from '@jsonforms/material-renderers';
import { JsonForms } from '@jsonforms/react';

const ingestionCatalogConnectorCreationMutation = graphql`
  mutation IngestionCatalogConnectorCreationMutation($input: AddManagedConnectorInput) {
    managedConnectorAdd(input: $input) {
      id
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

interface IngestionCatalogConnectorCreationProps {
  connector: IngestionConnector;
  open: boolean;
  onClose: () => void;
  contract: string;
}

interface ManagedConnectorValues {
  name: string;
  contract?: number;
  creator?: FieldOption;
  contractValues: Record<string, string | boolean>;
  confidence: number;
}

const IngestionCatalogConnectorCreation = ({ connector, open, onClose, contract }: IngestionCatalogConnectorCreationProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const [commitRegister] = useApiMutation(ingestionCatalogConnectorCreationMutation);

  const submitConnectorManagementCreation = (values: ManagedConnectorValues, {
    setSubmitting,
    resetForm,
  }: Partial<FormikHelpers<ManagedConnectorValues>>) => {
    const input = {
      name: values.name,
      connector_user_id: values.creator?.value,
      manager_contract_image: connector.container_image,
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
      title={t_i18n('Deploy a new connector')}
      open={open}
      onClose={onClose}
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
          creator: undefined,
          name: '',
          confidence: connector.max_confidence_level,
          ...connector.default
        }}
        onSubmit={() => {
        }}
      >
        {({ values, setFieldValue, isSubmitting, setSubmitting, resetForm, isValid }) => {
          return (
            <Form>
              {(connector) && (
                <>
                  <Field
                    component={TextField}
                    style={fieldSpacingContainerStyle}
                    variant="standard"
                    name="name"
                    label={t_i18n('Instance name')}
                    required
                    fullWidth={true}
                  />
                  <CreatorField
                    label={'User'}
                    containerStyle={fieldSpacingContainerStyle}
                    onChange={setFieldValue}
                    name="creator"
                    required
                  />
                  <ConfidenceField
                    containerStyle={fieldSpacingContainerStyle}
                    maxConfidenceLevel={connector.max_confidence_level}
                  />
                  <JsonForms
                    data={connector.default}
                    schema={connector as any}
                    renderers={materialRenderers}
                    validationMode={'NoValidation'}
                    onChange={({ data }) => setFieldValue('contractValues', data)}
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
                    submitConnectorManagementCreation(values, {
                      setSubmitting,
                      resetForm,
                    });
                  }}
                  disabled={!isValid || isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          );
        }}
      </Formik>
    </Drawer>
  );
};

export default IngestionCatalogConnectorCreation;
