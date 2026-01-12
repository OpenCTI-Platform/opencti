import React, { FunctionComponent } from 'react';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { graphql } from 'react-relay';
import { PayloadError, RecordSourceSelectorProxy } from 'relay-runtime';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { UserTokenCreationFormMutation$data } from './__generated__/UserTokenCreationFormMutation.graphql';

interface UserTokenCreationFormProps {
  userId: string;
  onSuccess: (token: string) => void;
  onClose: () => void;
}

const userTokenCreationMutation = graphql`
  mutation UserTokenCreationFormMutation($userId: ID!, $input: UserTokenAddInput!) {
    userAdminTokenAdd(userId: $userId, input: $input) {
      plaintext_token
      token_id
      expires_at
      masked_token
    }
  }
`;

const UserTokenCreationForm: FunctionComponent<UserTokenCreationFormProps> = ({
  userId,
  onSuccess,
  onClose,
}) => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    name: '',
    duration: 'legacy',
  };

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    duration: Yup.string().required(t_i18n('This field is required')),
  });

  const onSubmit = (values: typeof initialValues, { setSubmitting }: FormikHelpers<typeof initialValues>) => {
    let durationInput = 'UNLIMITED';
    switch (values.duration) {
      case '30':
        durationInput = 'DAYS_30';
        break;
      case '60':
        durationInput = 'DAYS_60';
        break;
      case '90':
        durationInput = 'DAYS_90';
        break;
      case '365':
        durationInput = 'DAYS_365';
        break;
      case 'legacy':
        durationInput = 'UNLIMITED';
        break;
      default:
        durationInput = 'UNLIMITED';
    }

    commitMutation({
      mutation: userTokenCreationMutation,
      variables: {
        userId,
        input: {
          name: values.name,
          duration: durationInput,
        },
      },
      updater: (store: RecordSourceSelectorProxy) => {
        const payload = store.getRootField('userAdminTokenAdd');
        if (!payload) return;

        const tokenId = payload.getValue('token_id');
        const expiresAt = payload.getValue('expires_at');
        const maskedToken = payload.getValue('masked_token');

        const userRecord = store.get(userId);
        if (!userRecord) return;

        const apiTokens = userRecord.getLinkedRecords('api_tokens') || [];

        const newTokenRecord = store.create(tokenId as string, 'ApiToken');
        newTokenRecord.setValue(tokenId, 'id');
        newTokenRecord.setValue(values.name, 'name');
        newTokenRecord.setValue(new Date().toISOString(), 'created_at');
        newTokenRecord.setValue(expiresAt, 'expires_at');
        newTokenRecord.setValue(maskedToken, 'masked_token');

        userRecord.setLinkedRecords([...apiTokens, newTokenRecord], 'api_tokens');
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: (response: UserTokenCreationFormMutation$data, errors: readonly PayloadError[] | null | undefined) => {
        setSubmitting(false);
        if (errors) {
          MESSAGING$.notifyError(errors[0].message);
          return;
        }
        const token = response.userAdminTokenAdd.plaintext_token;
        MESSAGING$.notifySuccess(t_i18n('Token generated successfully'));
        onSuccess(token);
      },
      onError: (error: Error) => {
        setSubmitting(false);
        MESSAGING$.notifyError(error.message);
      },
      setSubmitting,
    });
  };

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="duration"
            label={t_i18n('Duration')}
            fullWidth={true}
            containerstyle={fieldSpacingContainerStyle}
          >
            <MenuItem value="30">{t_i18n('30 days')}</MenuItem>
            <MenuItem value="60">{t_i18n('60 days')}</MenuItem>
            <MenuItem value="90">{t_i18n('90 days')}</MenuItem>
            <MenuItem value="365">{t_i18n('1 year')}</MenuItem>
            <MenuItem value="legacy">{t_i18n('Unlimited')}</MenuItem>
          </Field>
          <div style={{ float: 'right', marginTop: 20 }}>
            <Button
              variant="contained"
              color="secondary"
              onClick={onClose}
              style={{ marginRight: 10 }}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="primary"
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Generate')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default UserTokenCreationForm;
