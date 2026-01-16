import Button from '@common/button/Button';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import CoreForm from '@rjsf/core';
import JsonForm from '@rjsf/mui';
import { Field, Form, Formik } from 'formik';
import { FormikHelpers } from 'formik/dist/types';
import { createRef, FunctionComponent, MutableRefObject, useRef, useState } from 'react';
import { graphql, useQueryLoader } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { handleErrorInForm } from '../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { insertNode } from '../../../../utils/store';
import NotifierConnectorField from '../../common/form/NotifierConnectorField';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { NotifiersLinesPaginationQuery$variables } from './__generated__/NotifiersLinesPaginationQuery.graphql';
import { NotifierTestDialogQuery } from './__generated__/NotifierTestDialogQuery.graphql';
import NotifierTestDialog, { notifierTestQuery } from './NotifierTestDialog';
import { uiSchema } from './NotifierUtils';
import notifierValidator from './NotifierValidator';

const notifierMutation = graphql`
  mutation NotifierCreationMutation($input: NotifierAddInput!) {
    notifierAdd(input: $input) {
      id
      name
      description
      entity_type
      parent_types
      notifier_connector {
        name
      }
      ...NotifierLine_node
    }
  }
`;

interface NotifierAddInput {
  name: string;
  description: string;
  notifier_connector_id?: FieldOption;
  authorized_members: FieldOption[];
}

interface NotifierFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onClose?: () => void;
  inputValue?: string;
}

const notifierValidation = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  notifier_connector_id: Yup.object().required(t('This field is required')),
  authorized_members: Yup.array().nullable(),
});

type NotifierFormikHelpers = Pick<FormikHelpers<NotifierAddInput>,
'setErrors' | 'setSubmitting' | 'resetForm'>;

export const NotifierCreationForm: FunctionComponent<NotifierFormProps> = ({
  updater,
  onClose,
  inputValue,
}) => {
  const { t_i18n } = useFormatter();
  const formRef = createRef<CoreForm>();
  const [open, setOpen] = useState(false);
  const [connector, setCurrentConnector] = useState<FieldOption & { schema?: string; ui_schema?: string }>();
  const initialValues: NotifierAddInput = {
    name: inputValue || '',
    description: '',
    authorized_members: [],
  };
  const [commit] = useApiMutation(notifierMutation);
  const submitForm = (
    values: NotifierAddInput,
    current: MutableRefObject<CoreForm>['current'] | null,
    { setErrors, setSubmitting, resetForm }: NotifierFormikHelpers,
  ) => {
    notifierValidation(t_i18n)
      .validate(values)
      .then(() => {
        if (current && current.validateForm()) {
          const input = {
            name: values.name,
            description: values.description,
            notifier_connector_id: values.notifier_connector_id?.value,
            notifier_configuration: JSON.stringify(current.state.formData),
            authorized_members: values.authorized_members.map(({ value }) => ({
              id: value,
              access_right: 'view',
            })),
          };
          commit({
            variables: { input },
            updater: (store) => {
              if (updater) {
                updater(store, 'notifierAdd');
              }
            },
            onError: (error: Error) => {
              handleErrorInForm(error, setErrors);
              setSubmitting(false);
            },
            onCompleted: () => {
              setSubmitting(false);
              resetForm();
              if (onClose) {
                onClose();
              }
            },
          });
        }
      });
  };

  const notifierConfiguration = useRef<string>(' {}');
  const [testQueryRef, sendTest] = useQueryLoader<NotifierTestDialogQuery>(notifierTestQuery);
  return (
    <Formik<NotifierAddInput>
      initialValues={initialValues}
      validationSchema={notifierValidation(t_i18n)}
      onSubmit={() => {}}
      onReset={onClose}
    >
      {({
        setErrors,
        resetForm,
        handleReset,
        values,
        setSubmitting,
        isSubmitting,
        setFieldValue,
      }) => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
          />
          <Field
            component={TextField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          <NotifierConnectorField
            name="notifier_connector_id"
            onChange={(name, data) => setCurrentConnector(data)}
            style={{ marginTop: 20 }}
          />
          <ObjectMembersField
            label="Accessible for"
            style={fieldSpacingContainerStyle}
            onChange={setFieldValue}
            multiple={true}
            name="authorized_members"
          />
          {connector && (
            <JsonForm
              uiSchema={{
                ...JSON.parse(connector.ui_schema ?? ' {}'),
                ...uiSchema,
              }}
              ref={formRef}
              showErrorList={false}
              liveValidate
              validator={notifierValidator}
              schema={JSON.parse(connector.schema ?? ' {}')}
              formData={JSON.parse(notifierConfiguration.current)}
              onChange={(newValue) => {
                notifierConfiguration.current = JSON.stringify(
                  newValue.formData,
                );
              }}
            />
          )}
          <FormButtonContainer>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                notifierConfiguration.current = JSON.stringify(
                  formRef.current?.state.formData,
                );
                setOpen(true);
              }}
              disabled={isSubmitting}
            >
              {t_i18n('Test')}
            </Button>
            <Button
              color="secondary"
              onClick={() => submitForm(values, formRef.current, {
                setErrors,
                setSubmitting,
                resetForm,
              })
              }
            >
              {t_i18n('Create')}
            </Button>
          </FormButtonContainer>
          <NotifierTestDialog
            open={open}
            onClose={() => setOpen(false)}
            queryRef={testQueryRef}
            onTest={(notifier_test_id) => {
              if (values.notifier_connector_id) {
                sendTest(
                  {
                    input: {
                      notifier_test_id,
                      notifier_connector_id: values.notifier_connector_id.value,
                      notifier_configuration: notifierConfiguration.current,
                    },
                  },
                  { fetchPolicy: 'network-only' },
                );
              }
            }}
          />
        </Form>
      )}
    </Formik>
  );
};

const CreateNotifierControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="Notifier"
    {...props}
  />
);

const NotifierCreation: FunctionComponent<{
  contextual?: boolean;
  display?: boolean;
  inputValue?: string;
  paginationOptions: NotifiersLinesPaginationQuery$variables;
}> = ({ inputValue, paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_notifiers', paginationOptions, 'notifierAdd');
  return (
    <Drawer
      title={t_i18n('Create a notifier')}
      controlledDial={CreateNotifierControlledDial}
    >
      <NotifierCreationForm
        inputValue={inputValue}
        updater={updater}
      />
    </Drawer>
  );
};

export default NotifierCreation;
