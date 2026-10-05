import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { CheckCircleOutlined, ErrorOutlineOutlined, ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import { Alert, Spinner, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Label from '../../../components/common/label/Label';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import Security from '../../../utils/Security';
import useGranted, { MODULES_MODMANAGE } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { HUNT_DOCS, huntConnectorSetupDocumentation } from './hunt-utils';
import { notifyPayloadErrors } from './hunt-mutation-utils';
import { isStaleConnectionCheck } from './hunt-connection-check-utils';
import { HuntConnectorSetupTestConnectionMutation } from './__generated__/HuntConnectorSetupTestConnectionMutation.graphql';

const huntConnectorSetupTestConnectionMutation = graphql`
  mutation HuntConnectorSetupTestConnectionMutation($id: ID!) {
    huntConnectorTestConnection(id: $id) {
      connection_check {
        id
        status
      }
    }
  }
`;

interface RequiredPermission {
  readonly name: string;
  readonly purpose: string;
}

interface ConnectionCheck {
  readonly id: string;
  readonly status: string;
  readonly requested_at?: string | null;
  readonly checked_at?: string | null;
  readonly checks: ReadonlyArray<{ readonly name: string; readonly ok: boolean; readonly message: string }>;
}

/**
 * The permissions a hunt connector needs on its platform, as it declares them, with its setup documentation: the
 * "Before you start" block of its documentation, where the user configures it.
 */
export const HuntConnectorRequiredPermissions = ({ permissions, documentationUrl, defaultOpen = false }: {
  permissions: ReadonlyArray<RequiredPermission>;
  documentationUrl: string | null | undefined;
  defaultOpen?: boolean;
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
        {t_i18n('Required permissions')}
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
          {t_i18n('This hunt connector queries its platform with an account of its own: give that account the least-privilege permissions listed in its documentation. Once the connector runs, Test connection on its page checks them.')}
          {' '}
          <a href={huntConnectorSetupDocumentation(slug)} target="_blank" rel="noopener noreferrer" data-testid="hunt-connector-deployment-docs">
            {t_i18n('Read the setup documentation: account, permissions and configuration')}
          </a>
        </Text>
      )}
    />
  );
};

const ConnectionCheckResult = ({ check, requested }: { check: ConnectionCheck | null | undefined; requested: boolean }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const canTest = useGranted([MODULES_MODMANAGE]);
  const pending = requested || check?.status === 'pending';
  if (!check && !requested) {
    return (
      <Text variant="content-caption">
        {canTest
          ? t_i18n('Not tested yet: test the connection to check the account and its permissions')
          : t_i18n('Not tested yet: a user with the Manage connector state capability can test the connection')}
      </Text>
    );
  }
  if (pending) {
    const stale = !requested && isStaleConnectionCheck(check);
    return (
      <div data-testid="connector-hunt-check-status" data-status="pending" style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
        {!stale && <Spinner size="sm" />}
        <Text variant="content-caption">
          {stale
            ? t_i18n('No answer from the connector yet: it may run a version without connection tests, update it or read its logs')
            : t_i18n('Testing the connection on the platform')}
        </Text>
      </div>
    );
  }
  const passed = check?.status === 'passed';
  return (
    <div data-testid="connector-hunt-check-status" data-status={check?.status}>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
        {passed
          ? <CheckCircleOutlined fontSize="small" style={{ color: theme.palette.success.main }} />
          : <ErrorOutlineOutlined fontSize="small" style={{ color: theme.palette.error.main }} />}
        <Text variant="content-compact">
          {passed
            ? t_i18n('Connection test passed on {date}', { values: { date: fldt(check?.checked_at) } })
            : t_i18n('Connection test failed on {date}', { values: { date: fldt(check?.checked_at) } })}
        </Text>
      </div>
      <ul style={{ listStyle: 'none', margin: theme.spacing(1, 0, 0), padding: 0 }}>
        {(check?.checks ?? []).map((item) => (
          <li
            key={item.name}
            data-testid="connector-hunt-check-item"
            data-ok={item.ok}
            style={{ display: 'flex', alignItems: 'flex-start', gap: theme.spacing(1), padding: theme.spacing(0.5, 0) }}
          >
            {item.ok
              ? <CheckCircleOutlined fontSize="small" style={{ color: theme.palette.success.main }} />
              : <ErrorOutlineOutlined fontSize="small" style={{ color: theme.palette.error.main }} />}
            <span style={{ display: 'flex', flexDirection: 'column' }}>
              <Text variant="content-compact">{item.name}</Text>
              <Text variant="content-caption">{item.message}</Text>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
};

/**
 * Asks the hunt connector to test its connection and each permission it needs; the connector page refreshes the
 * answer, one plain-words result per check.
 */
export const HuntConnectorTestConnection = ({ connectorId, active, check }: {
  connectorId: string;
  active: boolean;
  check: ConnectionCheck | null | undefined;
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [requestedFor, setRequestedFor] = useState<string | null | undefined>(undefined);
  const [commit, inFlight] = useApiMutation<HuntConnectorSetupTestConnectionMutation>(huntConnectorSetupTestConnectionMutation);
  // Pending from the click until the refreshed connector shows a test other than the previous one
  const requested = requestedFor !== undefined && requestedFor === (check?.id ?? null);
  const testConnection = () => {
    setRequestedFor(check?.id ?? null);
    commit({
      variables: { id: connectorId },
      // A refused test (connector not running, no work) answers with payload errors: shown, and the button enabled again
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) {
          setRequestedFor(undefined);
        }
      },
      onError: () => setRequestedFor(undefined),
    });
  };
  return (
    <div data-testid="connector-hunt-connection">
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
        <Label>{t_i18n('Connection test')}</Label>
        <Security needs={[MODULES_MODMANAGE]}>
          <Button
            size="small"
            variant="secondary"
            onClick={testConnection}
            disabled={!active || inFlight || requested || (check?.status === 'pending' && !isStaleConnectionCheck(check))}
            data-testid="connector-hunt-test-connection"
          >
            {t_i18n('Test connection')}
          </Button>
        </Security>
      </div>
      {!active && (
        <Text variant="content-caption">{t_i18n('The connector is not running: start it, then test the connection')}</Text>
      )}
      <div style={{ marginTop: theme.spacing(1) }}>
        <ConnectionCheckResult check={check} requested={requested} />
      </div>
    </div>
  );
};
