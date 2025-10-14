import React, { FunctionComponent, useState } from 'react';
import { Add, VpnKey as VpnKeyIcon } from '@mui/icons-material';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { Field } from 'formik';
import { Paper, Tooltip } from '@mui/material';
import { useTheme } from '@mui/styles';
import AuthProviderForm, { AuthProvider } from '@components/settings/AuthProviderForm';
import AuthProviderPopover from '@components/settings/AuthProviderPopover';
import SwitchField from '../../../components/fields/SwitchField';
import { useFormatter } from '../../../components/i18n';
import ItemBoolean from '../../../components/ItemBoolean';
import type { Theme } from '../../../components/Theme';
import Drawer from '../common/drawer/Drawer';
import { Policies$data } from './__generated__/Policies.graphql';
import DataTableWithoutFragment from '../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';

interface SSOConfigurationProps {
  existingProviders?: Policies$data['platform_providers'];
  handleSubmitField: (name: string, value: AuthProvider | AuthProvider[] | string, objectPath?: string) => void;
}

const LOCAL_STORAGE_KEY = 'Auth_Providers';

const SSOConfiguration: FunctionComponent<SSOConfigurationProps> = ({ existingProviders = [], handleSubmitField }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const [drawerOpen, setDrawerOpen] = useState(false);

  const handleDrawerClose = () => {
    setDrawerOpen(false);
  };

  const dataColumns = {
    identifier: {
      label: 'identifier',
      percentWidth: 70,
      isSortable: false,
      render: (provider: AuthProvider) => (
        <Box display="flex" alignItems="center" gap={1}>
          {provider.identifier}
          {!provider.dynamic && (
            <Chip size="small" label={t_i18n('Config file')} color="primary" />
          )}
        </Box>
      ),
    },
    strategy: {
      label: 'Strategy',
      percentWidth: 15,
      isSortable: false,
      render: ({ strategy }: AuthProvider) => defaultRender(strategy),
    },
    status: {
      label: 'Status',
      percentWidth: 15,
      isSortable: false,
      render: ({ disabled, valid }: AuthProvider) => {
        const status = !valid ? null : !disabled;
        return (
          <ItemBoolean
            variant="inList"
            label={disabled ? t_i18n('Disabled') : t_i18n('Enabled')}
            neutralLabel={t_i18n('Invalid')}
            status={status}
          />
        );
      },
    },
  };

  const handleDelete = (p: AuthProvider) => {
    const providers: AuthProvider[] = existingProviders.filter((provider) => provider.identifier !== p.identifier && provider.dynamic);
    handleSubmitField('platform_providers', providers.map(({ identifier, type, strategy, config, disabled }) => ({ identifier, type, strategy, config, disabled })));
  };

  const handleUpdate = (updatedProvider: AuthProvider) => {
    const providers = existingProviders
      .filter(({ dynamic }) => dynamic)
      .map((provider) => provider.identifier === updatedProvider.identifier ? updatedProvider : provider);
    handleSubmitField('platform_providers', providers.map(({ identifier, type, strategy, config, disabled }) => ({ identifier, type, strategy, config, disabled })));
  };

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: -10 }}>
        <Typography variant="h4" gutterBottom>
          {t_i18n('Authentication strategies')}
        </Typography>
        <Drawer
          open={drawerOpen}
          onClose={handleDrawerClose}
          title={t_i18n('Create provider')}
          controlledDial={({ onOpen }) => (
            <Tooltip title={t_i18n('Create an authentication provider for the platform.')}>
              <IconButton style={{ marginTop: -7 }} size="small" onClick={onOpen} color="primary"><Add /></IconButton>
            </Tooltip>
          )}
        >
          <AuthProviderForm
            onClose={handleDrawerClose}
            onCreate={(p: AuthProvider) => {
              const dynamicProviders = existingProviders.filter((provider) => provider.dynamic);
              if (dynamicProviders.length > 0) {
                handleSubmitField('platform_providers', p, `/platform_providers/${dynamicProviders.length}`);
              } else {
                handleSubmitField('platform_providers', [p]);
              }
            }}
          />
        </Drawer>
      </div>
      <Paper
        style={{
          marginTop: 10,
          padding: theme.spacing(1),
        }}
        className={'paper-for-grid'}
        variant="outlined"
      >
        <DataTableWithoutFragment
          dataColumns={dataColumns}
          storageKey={LOCAL_STORAGE_KEY}
          data={existingProviders}
          globalCount={existingProviders.length}
          variant={DataTableVariant.inline}
          icon={() => <VpnKeyIcon color="primary" />}
          actions={(p) => <AuthProviderPopover provider={p} onDelete={handleDelete} onUpdate={handleUpdate} />}
          disableNavigation
        />
        <Field
          component={SwitchField}
          type="checkbox"
          name="otp_mandatory"
          label={t_i18n('Enforce two-factor authentication')}
          containerstyle={{ margin: theme.spacing(2), width: 'fit-content' }}
          onChange={(name: string, value: string) => handleSubmitField(name, value)}
          tooltip={t_i18n(
            'When enforcing 2FA authentication, all users will be asked to enable 2FA to be able to login in the platform.',
          )}
        />
      </Paper>
    </>
  );
};

export default SSOConfiguration;
