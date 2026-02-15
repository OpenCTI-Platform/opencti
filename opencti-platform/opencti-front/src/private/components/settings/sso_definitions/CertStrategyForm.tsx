import React from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import type { CertStrategyFormQuery } from './__generated__/CertStrategyFormQuery.graphql';
import type { CertStrategyFormMutation } from './__generated__/CertStrategyFormMutation.graphql';

const certStrategyFormQuery = graphql`
  query CertStrategyFormQuery {
    settings {
      id
      cert_auth {
        enabled
        button_label
      }
    }
  }
`;

const certStrategyFormMutation = graphql`
  mutation CertStrategyFormMutation($id: ID!, $input: CertAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateCertAuth(input: $input) {
        id
        cert_auth {
          enabled
          button_label
        }
      }
    }
  }
`;

const validationSchema = Yup.object().shape({
  enabled: Yup.boolean(),
  button_label: Yup.string().nullable(),
});

interface CertStrategyFormProps {
  onCancel: () => void;
}

const CertStrategyForm = ({ onCancel }: CertStrategyFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const data = useLazyLoadQuery<CertStrategyFormQuery>(certStrategyFormQuery, {});
  const settings = data.settings;
  const certAuth = settings.cert_auth;

  const [commitMutation] = useApiMutation<CertStrategyFormMutation>(
    certStrategyFormMutation,
    undefined,
    { successMessage: t_i18n('Authentication successfully updated') },
  );

  const initialValues = {
    enabled: certAuth?.enabled ?? false,
    button_label: certAuth?.button_label ?? '',
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
          enabled: values.enabled,
          button_label: values.button_label || null,
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
          <Field
            component={SwitchField}
            type="checkbox"
            name="enabled"
            label={t_i18n('Enable client certificate authentication')}
          />
          <Field
            component={TextField}
            variant="standard"
            name="button_label"
            label={t_i18n('Button label')}
            fullWidth
            style={{ marginTop: 20 }}
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

export default CertStrategyForm;
