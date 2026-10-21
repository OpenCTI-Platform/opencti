import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import { ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import { Alert, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { HUNT_DOCS, huntConnectorSetupDocumentation } from './hunt-utils';

interface RequiredPermission {
  readonly name: string;
  readonly purpose: string;
}

/**
 * The permissions a hunt connector needs on its platform, as it declares them, with its setup documentation: the
 * "Before you start" block of its documentation, where the user configures it.
 */
export const HuntConnectorRequiredPermissions = ({ permissions, documentationUrl, defaultOpen = false, label }: {
  permissions: ReadonlyArray<RequiredPermission>;
  documentationUrl: string | null | undefined;
  defaultOpen?: boolean;
  label?: string;
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(defaultOpen);
  const documentation = documentationUrl || HUNT_DOCS.connectors;
  return (
    <div data-testid="connector-hunt-permissions" data-open={open}>
      <Button
        size="small"
        variant="tertiary"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        startIcon={open ? <ExpandLessOutlined /> : <ExpandMoreOutlined />}
        data-testid="connector-hunt-permissions-toggle"
      >
        {label ?? t_i18n('Required permissions')}
      </Button>
      {open && (
        <div style={{ marginTop: theme.spacing(1) }}>
          {permissions.length > 0 ? (
            <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 2fr)', gap: theme.spacing(1, 2) }}>
              {permissions.map((permission) => (
                <React.Fragment key={permission.name}>
                  <dt><Text variant="content-compact"><code>{permission.name}</code></Text></dt>
                  <dd style={{ margin: 0 }}><Text variant="content-caption">{permission.purpose}</Text></dd>
                </React.Fragment>
              ))}
            </dl>
          ) : (
            <Text variant="content-caption">{t_i18n('This connector does not list its permissions: its documentation gives them')}</Text>
          )}
          <div style={{ marginTop: theme.spacing(1) }}>
            <a href={documentation} target="_blank" rel="noopener noreferrer" data-testid="connector-hunt-permissions-docs">
              {t_i18n('Read the setup documentation: account, permissions and configuration')}
            </a>
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * Where a hunt connector is deployed or configured, before it registers its permissions: the account it needs and the
 * section of the documentation giving its permissions, console steps and configuration.
 */
export const HuntConnectorDeploymentNotice = ({ slug }: { slug: string | null | undefined }) => {
  const { t_i18n } = useFormatter();
  return (
    <Alert
      severity="info"
      title={t_i18n('Before you start: the account of the hunt connector')}
      data-testid="hunt-connector-deployment-notice"
      description={(
        <Text variant="content-caption" style={{ display: 'block' }}>
          {t_i18n('This hunt connector queries its platform with an account of its own: give that account the least-privilege permissions listed in its documentation.')}
          {' '}
          <a href={huntConnectorSetupDocumentation(slug)} target="_blank" rel="noopener noreferrer" data-testid="hunt-connector-deployment-docs">
            {t_i18n('Read the setup documentation: account, permissions and configuration')}
          </a>
        </Text>
      )}
    />
  );
};
