import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import CoreForm from '@rjsf/core';
import JsonForm from '@rjsf/mui';
import type { RJSFSchema } from '@rjsf/utils';
import { Field, Form, Formik } from 'formik';
import { FormikHelpers } from 'formik/dist/types';
import React, { createRef, FunctionComponent, useRef, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader } from 'react-relay';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { AutoCompleteOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import NotifierConnectorField from '../../common/form/NotifierConnectorField';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { Option } from '../../common/form/ReferenceField';
import { NotifierEdition_edition$key } from './__generated__/NotifierEdition_edition.graphql';
import { NotifierEditionQuery } from './__generated__/NotifierEditionQuery.graphql';
import { NotifierTestDialogQuery } from './__generated__/NotifierTestDialogQuery.graphql';
import NotifierTestDialog, { notifierTestQuery } from './NotifierTestDialog';
import { uiSchema } from './NotifierUtils';
import notifierValidator from './NotifierValidator';
import { handleErrorInForm } from '../../../../relay/environment';
import { convertAuthorizedMembers } from '../../../../utils/edition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const notifierMutationFieldPatch = graphql`
  mutation NotifierEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    notifierFieldPatch(id: $id, input: $input) {
      ...NotifierLine_node
      ...NotifierEdition_edition
    }
  }
`;

const notifierEditionFragment = graphql`
  fragment NotifierEdition_edition on Notifier {
    id
    name
    description
    notifier_connector {
      id
      name
      connector_schema
      connector_schema_ui
    }
    notifier_connector_id
    notifier_configuration
    authorized_members {
      id
      member_id
      name
      access_right
    }
  }
`;

export const notifierEditionQuery = graphql`
  query NotifierEditionQuery($id: String!) {
    notifier(id: $id) {
      ...NotifierEdition_edition
    }
  }
`;

const notifierValidation = (t: (n: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

interface NotifierEditionComponentProps {
  queryRef: PreloadedQuery<NotifierEditionQuery>
  onClose: () => void
}

interface NotifierEditionValues {
  name: string
  description?: string | null
  restricted_members?: AutoCompleteOption[] | null
  notifier_connector_id?: Option
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type FormRef = React.RefObject<CoreForm<any, RJSFSchema, any>>['current'];

const NotifierEdition: FunctionComponent<NotifierEditionComponentProps> = ({
  queryRef,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const formRef = createRef<CoreForm>();

  const [open, setOpen] = useState(false);

  const { notifier } = usePreloadedQuery<NotifierEditionQuery>(notifierEditionQuery, queryRef);
  const data = useFragment<NotifierEdition_edition$key>(notifierEditionFragment, notifier);

  const [commitFieldPatch] = useApiMutation(notifierMutationFieldPatch);
  const initialValues: NotifierEditionValues = {
    name: data?.name ?? '',
    description: data?.description,
    restricted_members: convertAuthorizedMembers(data),
    notifier_connector_id: data?.notifier_connector ? { value: data.notifier_connector.id, label: data.notifier_connector.name } : undefined,
  };
  const submitForm = (
    setSubmitting: FormikHelpers<NotifierEditionValues>['setSubmitting'],
    setErrors: FormikHelpers<NotifierEditionValues>['setErrors'],
    values: NotifierEditionValues,
    current: FormRef,
  ) => {
    notifierValidation(t_i18n)
      .validate(values)
      .then(() => {
        if (current?.validateForm()) {
          setSubmitting(true);
          const inputs = [
            { key: 'name', value: [values.name] },
            { key: 'description', value: [values.description] },
            { key: 'restricted_members', value: values.restricted_members?.map(({ value }) => value) },
            { key: 'notifier_connector_id', value: [values.notifier_connector_id?.value] },
            { key: 'notifier_configuration', value: [JSON.stringify(current.state.formData)] },
          ];
          commitFieldPatch({
            variables: { id: data?.id, input: inputs },
            onError: (error: Error) => {
              handleErrorInForm(error, setErrors);
              setSubmitting(false);
            },
            onCompleted: () => {
              setSubmitting(false);
              onClose();
            },
          });
        }
      });
  };

  const notifierConfiguration = useRef<string>(data?.notifier_configuration ?? ' {}');

  const [testQueryRef, sendTest, resetTest] = useQueryLoader<NotifierTestDialogQuery>(notifierTestQuery);
  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={notifierValidation(t_i18n)}
        onSubmit={() => {}}
        onClose={onClose}
      >
        {({ values, setFieldValue, setSubmitting, setErrors, isSubmitting }) => (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
            />
            <Field
              component={TextField}
              name="description"
              variant="standard"
              label={t_i18n('Description')}
              fullWidth={true}
              style={{ marginTop: 20 }}
            />
            <NotifierConnectorField
              disabled={true}
              name="notifier_connector_id"
              style={{ marginTop: 20 }}
            />
            <ObjectMembersField
              label={'Accessible for'}
              style={fieldSpacingContainerStyle}
              onChange={setFieldValue}
              multiple={true}
              name="restricted_members"
            />
            <JsonForm
              uiSchema={{
                ...JSON.parse(data?.notifier_connector?.connector_schema_ui ?? ' {}'),
                ...uiSchema,
              }}
              ref={formRef}
              showErrorList={false}
              liveValidate
              schema={JSON.parse(data?.notifier_connector?.connector_schema ?? ' {}')}
              formData={JSON.parse(notifierConfiguration.current)}
              validator={notifierValidator}
              onChange={(newValue) => {
                notifierConfiguration.current = JSON.stringify(newValue.formData);
              }}
            />
            <div className={classes.buttons}>
              <Button
                variant="contained"
                color="primary"
                onClick={() => {
                  notifierConfiguration.current = JSON.stringify(formRef.current?.state.formData);
                  setOpen(true);
                }}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Test')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={() => {
                  submitForm(setSubmitting, setErrors, values, formRef.current);
                }}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Save')}
              </Button>
            </div>
            <NotifierTestDialog
              open={open}
              onClose={() => {
                setOpen(false);
                resetTest();
              }}
              queryRef={testQueryRef}
              onTest={(notifier_test_id) => {
                if (values.notifier_connector_id) {
                  sendTest({
                    input: {
                      notifier_test_id,
                      notifier_connector_id: values.notifier_connector_id.value,
                      notifier_configuration: notifierConfiguration.current,
                    },
                  }, { fetchPolicy: 'network-only' });
                }
              }}
            />
          </Form>
        )}
      </Formik>
    </div>
  );
};

export default NotifierEdition;
