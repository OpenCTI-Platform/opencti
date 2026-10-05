import React from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Stack, Typography } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import { SOURCE_INTELLIGENCE_DOCUMENTATION_URL } from './sourceIntelligenceUtils';

export interface ConnectorRequiredSetting {
  readonly key: string;
  readonly label: string;
  readonly description: string | null | undefined;
  readonly type: string;
  readonly secret: boolean;
}

export interface ConnectorSettingValue {
  key: string;
  value: string;
}

// Setting types the dialog collects as one value; a connector needing another type is deployed from its catalog page
const COLLECTABLE_SETTING_TYPES = ['string', 'integer', 'number', 'boolean'];

export const hasOnlyCollectableSettings = (settings: readonly ConnectorRequiredSetting[]) => {
  return settings.every((setting) => COLLECTABLE_SETTING_TYPES.includes(setting.type));
};

/** Service account a one-click deployment creates for the connector (see the add_connector recommendation). */
export const deployedConnectorAccount = (connectorName: string) => `[C] ${connectorName}`;

interface ConnectorDeployDialogProps {
  open: boolean;
  connectorName: string;
  settings: readonly ConnectorRequiredSetting[];
  deploying: boolean;
  onClose: () => void;
  onDeploy: (configuration: ConnectorSettingValue[]) => void;
}

/**
 * Confirmation of a one-click deployment: what the connector needs from its catalog contract, collected here, and the
 * account it runs as, with where both can be changed afterwards.
 */
const ConnectorDeployDialog = ({ open, connectorName, settings, deploying, onClose, onDeploy }: ConnectorDeployDialogProps) => {
  const { t_i18n } = useFormatter();
  const initialValues = Object.fromEntries(settings.map((setting) => [setting.key, setting.type === 'boolean' ? false : '']));
  const validation = Yup.object().shape(Object.fromEntries(settings
    .filter((setting) => setting.type !== 'boolean')
    .map((setting) => {
      const numeric = setting.type === 'integer' || setting.type === 'number';
      const base = numeric
        ? Yup.number().typeError(t_i18n('This field must be a number'))
        : Yup.string().trim();
      return [setting.key, base.required(t_i18n('This field is required'))];
    })));
  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Deploy {name}', { values: { name: connectorName } })} size="small">
      <Formik<Record<string, string | boolean>>
        initialValues={initialValues}
        validationSchema={validation}
        enableReinitialize
        onSubmit={(values) => onDeploy(settings.map((setting) => ({ key: setting.key, value: String(values[setting.key]).trim() })))}
      >
        {({ submitForm }) => (
          <Form data-testid="connector-deploy-dialog">
            <Stack gap={2}>
              <Typography variant="body2">
                {settings.length > 0
                  ? t_i18n('The catalog contract of this connector requires these settings. They are sent to XTM Composer for this deployment only and are not kept with the recommendation.')
                  : t_i18n('The catalog contract of this connector requires no setting: it starts with the default settings of the catalog.')}
              </Typography>
              {settings.map((setting) => (setting.type === 'boolean' ? (
                <Field
                  key={setting.key}
                  component={SwitchField}
                  type="checkbox"
                  name={setting.key}
                  label={setting.label}
                  helpertext={setting.description ?? undefined}
                />
              ) : (
                <Field
                  key={setting.key}
                  component={TextField}
                  variant="standard"
                  name={setting.key}
                  label={setting.label}
                  type={setting.secret ? 'password' : (setting.type === 'string' ? 'text' : 'number')}
                  autoComplete={setting.secret ? 'new-password' : 'off'}
                  helperText={setting.description ?? undefined}
                  required
                  fullWidth
                />
              )))}
              <Typography variant="body2" data-testid="connector-deploy-account">
                {t_i18n('The connector runs as a new service account, {account}, with a confidence level of 50. After the deployment, change its settings from its page in Integrations > Deployed, and its account in Settings > Security > Users.', {
                  values: { account: deployedConnectorAccount(connectorName) },
                })}
              </Typography>
            </Stack>
            <FormButtonContainer>
              <Button variant="tertiary" component="a" href={`${SOURCE_INTELLIGENCE_DOCUMENTATION_URL}#collection-gaps-ee`} target="_blank" rel="noopener noreferrer">
                {t_i18n('Learn more')}
              </Button>
              <Button variant="secondary" onClick={onClose} disabled={deploying}>{t_i18n('Cancel')}</Button>
              <Button onClick={submitForm} disabled={deploying} data-testid="connector-deploy-submit">{t_i18n('Deploy')}</Button>
            </FormButtonContainer>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default ConnectorDeployDialog;
