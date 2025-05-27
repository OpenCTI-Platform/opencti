import { SecurityPlatformsPaginationQuery$variables } from '@components/entities/__generated__/SecurityPlatformsPaginationQuery.graphql';
import React, { FunctionComponent } from 'react';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import TextField from '../../../../components/TextField';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import type { Theme } from '../../../../components/Theme';
import { FieldOption } from '../../../../utils/field';

interface SecurityPlatformCreationProps {
  paginationOptions: SecurityPlatformsPaginationQuery$variables
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

export interface SecurityPlatformCreationFormData {
  name: string;
  description: string
  security_platform_type: string | undefined
  createdBy: FieldOption | undefined
  objectLabel: FieldOption[]
  objectMarking: FieldOption[]
}

const securityPlatformCreationMutation = graphql`
mutation SecurityPlatformCreationAddMutation($input: SecurityPlatformAddInput!) {
    securityPlatformAdd(input: $input) {
        ...SecurityPlatform_securityPlatform
    }
}
`;

const CreateSecurityPlatformControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial entityType='security_Platform' {...props} />
);

const SecurityPlatformCreation: FunctionComponent<SecurityPlatformCreationProps> = ({
  paginationOptions,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const initialValues: SecurityPlatformCreationFormData = {
    name: '',
    description: '',
    security_platform_type: undefined,
    createdBy: defaultCreatedBy ?? undefined,
    objectLabel: [],
    objectMarking: defaultMarkingDefinitions ?? [],
  };

  const updater = (store: RecordSourceSelectorProxy, rootField: string) => {
    insertNode(
      store,
      'Pagination_securityPlatforms',
      paginationOptions,
      rootField,
    );
  };

  const [commit] = useApiMutation(securityPlatformCreationMutation);

  const onSubmit: FormikConfig<SecurityPlatformCreationFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const input = {
      name: values.name,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        updater(store, 'securityPlatformAdd');
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <Drawer
      title={t_i18n('Create a Security Platform')}
      controlledDial={CreateSecurityPlatformControlledDial}
    >
      {({ onClose }) => (
        <Formik<SecurityPlatformCreationFormData>
          initialValues={initialValues}
          // validationSchema={SecurityPlatformValidation(t_i18n)}
          onSubmit={(values, formikHelpers) => {
            onSubmit(values, formikHelpers);
            onClose();
          }}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <div style={{ marginTop: theme.spacing(2), textAlign: 'right' }}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  style={{ marginLeft: theme.spacing(2) }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  style={{ marginLeft: theme.spacing(2) }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default SecurityPlatformCreation;
