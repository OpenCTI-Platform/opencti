import React from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import type { LocalStrategyFormQuery } from './__generated__/LocalStrategyFormQuery.graphql';
import type { LocalStrategyFormMutation } from './__generated__/LocalStrategyFormMutation.graphql';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const localStrategyFormQuery = graphql`
  query LocalStrategyFormQuery {
    settings {
      id
      local_auth {
        enabled
      }
      password_policy_min_length
      password_policy_max_length
      password_policy_min_symbols
      password_policy_min_numbers
      password_policy_min_words
      password_policy_min_lowercase
      password_policy_min_uppercase
    }
  }
`;

const localStrategyFormMutation = graphql`
  mutation LocalStrategyFormMutation($id: ID!, $input: LocalAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateLocalAuth(input: $input) {
        id
        local_auth {
          enabled
        }
        password_policy_min_length
        password_policy_max_length
        password_policy_min_symbols
        password_policy_min_numbers
        password_policy_min_words
        password_policy_min_lowercase
        password_policy_min_uppercase
      }
    }
  }
`;

const validationSchema = Yup.object().shape({
  enabled: Yup.boolean(),
  password_policy_min_length: Yup.number(),
  password_policy_max_length: Yup.number(),
  password_policy_min_symbols: Yup.number(),
  password_policy_min_numbers: Yup.number(),
  password_policy_min_words: Yup.number(),
  password_policy_min_lowercase: Yup.number(),
  password_policy_min_uppercase: Yup.number(),
});

interface LocalStrategyFormProps {
  onCancel: () => void;
}

const LocalStrategyForm = ({ onCancel }: LocalStrategyFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const data = useLazyLoadQuery<LocalStrategyFormQuery>(localStrategyFormQuery, {});
  const settings = data.settings;

  const [commitMutation] = useApiMutation<LocalStrategyFormMutation>(
    localStrategyFormMutation,
    undefined,
    { successMessage: t_i18n('Authentication successfully updated') },
  );

  const localAuth = settings.local_auth;

  const initialValues = {
    enabled: isEnterpriseEdition ? true : (localAuth?.enabled ?? false),
    password_policy_min_length: settings.password_policy_min_length ?? 0,
    password_policy_max_length: settings.password_policy_max_length ?? 0,
    password_policy_min_symbols: settings.password_policy_min_symbols ?? 0,
    password_policy_min_numbers: settings.password_policy_min_numbers ?? 0,
    password_policy_min_words: settings.password_policy_min_words ?? 0,
    password_policy_min_lowercase: settings.password_policy_min_lowercase ?? 0,
    password_policy_min_uppercase: settings.password_policy_min_uppercase ?? 0,
  };

  const handleSubmit = (
    values: typeof initialValues,
    { setSubmitting }: { setSubmitting: (flag: boolean) => void },
  ) => {
    setSubmitting(true);
    commitMutation({
      variables: {
        id: settings.id,
        input: {
          enabled: isEnterpriseEdition ? true : values.enabled,
          password_policy_min_length: Number(values.password_policy_min_length) || 0,
          password_policy_max_length: Number(values.password_policy_max_length) || 0,
          password_policy_min_symbols: Number(values.password_policy_min_symbols) || 0,
          password_policy_min_numbers: Number(values.password_policy_min_numbers) || 0,
          password_policy_min_words: Number(values.password_policy_min_words) || 0,
          password_policy_min_lowercase: Number(values.password_policy_min_lowercase) || 0,
          password_policy_min_uppercase: Number(values.password_policy_min_uppercase) || 0,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        onCancel();
      },
      onError: () => {
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik
      enableReinitialize
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={handleSubmit}
      onReset={onCancel}
    >
      {({ handleReset, submitForm, isSubmitting }) => (
        <Form>
          {isEnterpriseEdition && (
            <Field
              component={SwitchField}
              type="checkbox"
              name="enabled"
              disabled={!isEnterpriseEdition}
              label={t_i18n('Enable local authentication')}
            />
          )}
          <Typography variant="h4" gutterBottom style={{ marginBottom: 20, marginTop: isEnterpriseEdition ? 20 : 0 }}>
            {t_i18n('Local password policies')}
          </Typography>
          <Field
            component={TextField}
            type="number"
            variant="standard"
            name="password_policy_min_length"
            label={t_i18n('Number of chars must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="standard"
            style={{ marginTop: 20 }}
            name="password_policy_max_length"
            label={`${t_i18n('Number of chars must be lower or equals to')} (${t_i18n('0 equals no maximum')})`}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="standard"
            style={{ marginTop: 20 }}
            name="password_policy_min_symbols"
            label={t_i18n('Number of symbols must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="standard"
            style={{ marginTop: 20 }}
            name="password_policy_min_numbers"
            label={t_i18n('Number of digits must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="standard"
            style={{ marginTop: 20 }}
            name="password_policy_min_words"
            label={t_i18n('Number of words (split on hyphen, space) must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="standard"
            style={{ marginTop: 20 }}
            name="password_policy_min_lowercase"
            label={t_i18n('Number of lowercase chars must be greater or equals to')}
            fullWidth
          />
          <Field
            component={TextField}
            type="number"
            variant="standard"
            style={{ marginTop: 20 }}
            name="password_policy_min_uppercase"
            label={t_i18n('Number of uppercase chars must be greater or equals to')}
            fullWidth
          />
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Update')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default LocalStrategyForm;
