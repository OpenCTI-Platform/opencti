import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import EditOutlined from '@mui/icons-material/EditOutlined';
import ListOutlined from '@mui/icons-material/ListOutlined';
import { WarningAmberOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Drawer from '@components/common/drawer/Drawer';
import LocalStrategyForm from './LocalStrategyForm';
import CertStrategyForm from './CertStrategyForm';
import HeaderStrategyForm from './HeaderStrategyForm';
import AuthLogsByIdentifierDrawer, { AUTH_IDENTIFIER_HEADERS, AUTH_IDENTIFIER_CERT } from './AuthLogsByIdentifierDrawer';
import type { SSOSingletonStrategiesQuery } from './__generated__/SSOSingletonStrategiesQuery.graphql';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '@components/common/entreprise_edition/EEChip';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import type { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';

type StrategyType = 'local' | 'cert' | 'header';

interface StrategyRow {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  strategy: StrategyType;
}

const ssoSingletonStrategiesQuery = graphql`
  query SSOSingletonStrategiesQuery {
    settings {
      id
      local_auth {
        enabled
      }
      cert_auth {
        enabled
      }
      headers_auth {
        enabled
      }
      platform_https_enabled
    }
  }
`;

const STRATEGY_LOG_IDENTIFIER: Record<string, string> = {
  header: AUTH_IDENTIFIER_HEADERS,
  cert: AUTH_IDENTIFIER_CERT,
};

const SSOSingletonStrategiesContent = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const [editingStrategy, setEditingStrategy] = useState<StrategyType | null>(null);
  const [logsDrawer, setLogsDrawer] = useState<{ identifier: string; name: string } | null>(null);

  const data = useLazyLoadQuery<SSOSingletonStrategiesQuery>(ssoSingletonStrategiesQuery, {});
  const { settings } = data;

  const localEnabled = settings.local_auth?.enabled ?? false;
  const certEnabled = settings.cert_auth?.enabled ?? false;
  const headerEnabled = settings.headers_auth?.enabled ?? false;
  const isHttpsEnabled = settings.platform_https_enabled;

  const strategiesData: StrategyRow[] = [
    { id: 'local', name: t_i18n('Local'), type: t_i18n('FORM'), enabled: localEnabled, strategy: 'local' },
    { id: 'header', name: t_i18n('HTTP headers'), type: t_i18n('SSO'), enabled: headerEnabled, strategy: 'header' },
    { id: 'cert', name: t_i18n('Client Certificate'), type: t_i18n('SSO'), enabled: certEnabled, strategy: 'cert' },
  ];

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      label: t_i18n('Configuration name'),
      percentWidth: 45,
      isSortable: false,
      render: (node: StrategyRow) => node.name,
    },
    type: {
      label: t_i18n('Authentication type'),
      percentWidth: 40,
      isSortable: false,
      render: (node: StrategyRow) => node.type,
    },
    enabled: {
      label: t_i18n('Status'),
      percentWidth: 15,
      isSortable: false,
      render: (node: StrategyRow) => {
        const showEE = node.strategy !== 'local' && !isEnterpriseEdition;
        const isEnabled = node.enabled && (node.strategy !== 'cert' || isHttpsEnabled) && (node.strategy === 'local' || isEnterpriseEdition);
        const showCertHttpsInfo = node.strategy === 'cert' && !isHttpsEnabled;
        return (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, opacity: 1 }}>
            <ItemBoolean
              label={isEnabled ? t_i18n('Enabled') : t_i18n('Disabled')}
              status={isEnabled}
            />
            {showEE && <span onClick={(e) => e.stopPropagation()}><EEChip /></span>}
            {showCertHttpsInfo && (
              <Tooltip title={t_i18n('Client certificate requires the platform to be configured with HTTPS')}>
                <span>
                  <IconButton
                    size="small"
                    disabled
                    sx={{
                      padding: 0.25,
                      color: 'warning.main',
                      '&.Mui-disabled': { color: 'warning.main', opacity: 1 },
                    }}
                  >
                    <WarningAmberOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            )}
          </Box>
        );
      },
    },
  };

  const handleLineClick = (node: StrategyRow) => {
    setEditingStrategy(node.strategy);
  };

  const drawerTitles: Record<StrategyType, string> = {
    local: t_i18n('Update Local Authentication'),
    cert: t_i18n('Update Client Certificate Authentication'),
    header: t_i18n('Update HTTP Headers Authentication'),
  };

  return (
    <div style={{ marginBottom: 30 }}>
      <DataTableWithoutFragment
        storageKey="SSOSingletonStrategies"
        dataColumns={dataColumns}
        data={strategiesData}
        globalCount={strategiesData.length}
        onLineClick={handleLineClick}
        disableToolBar
        disableNavigation
        disableLineSelection
        isLocalStorageEnabled={false}
        actionsColumnWidth={72}
        actions={(node: StrategyRow) => {
          const showLogs = node.strategy === 'header' || node.strategy === 'cert';
          return (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Tooltip title={t_i18n('Update')}>
                <IconButton
                  size="small"
                  onClick={(e) => {
                    e.stopPropagation();
                    setEditingStrategy(node.strategy);
                  }}
                  aria-label={t_i18n('Update')}
                >
                  <EditOutlined fontSize="small" />
                </IconButton>
              </Tooltip>
              {showLogs && (
                <Tooltip title={t_i18n('Logs')}>
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      setLogsDrawer({
                        identifier: STRATEGY_LOG_IDENTIFIER[node.strategy],
                        name: node.name,
                      });
                    }}
                    aria-label={t_i18n('Logs')}
                  >
                    <ListOutlined fontSize="small" />
                  </IconButton>
                </Tooltip>
              )}
            </Box>
          );
        }}
      />

      {editingStrategy && (
        <Drawer
          title={drawerTitles[editingStrategy]}
          open={!!editingStrategy}
          onClose={() => setEditingStrategy(null)}
        >
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            {editingStrategy === 'local' && <LocalStrategyForm onCancel={() => setEditingStrategy(null)} />}
            {editingStrategy === 'cert' && <CertStrategyForm onCancel={() => setEditingStrategy(null)} />}
            {editingStrategy === 'header' && <HeaderStrategyForm onCancel={() => setEditingStrategy(null)} />}
          </Suspense>
        </Drawer>
      )}
      {logsDrawer && (
        <AuthLogsByIdentifierDrawer
          isOpen
          onClose={() => setLogsDrawer(null)}
          identifier={logsDrawer.identifier}
          name={logsDrawer.name}
        />
      )}
    </div>
  );
};

const SSOSingletonStrategies = () => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <SSOSingletonStrategiesContent />
  </Suspense>
);

export default SSOSingletonStrategies;
