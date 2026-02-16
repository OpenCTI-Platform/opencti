import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import EditOutlined from '@mui/icons-material/EditOutlined';
import { InfoOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Card from '../../../../components/common/card/Card';
import Drawer from '@components/common/drawer/Drawer';
import LocalStrategyForm from './LocalStrategyForm';
import CertStrategyForm from './CertStrategyForm';
import HeaderStrategyForm from './HeaderStrategyForm';
import type { SSOSingletonStrategiesQuery } from './__generated__/SSOSingletonStrategiesQuery.graphql';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '@components/common/entreprise_edition/EEChip';

type StrategyType = 'local' | 'cert' | 'header';

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

const rowSx = (theme: Theme, isLast: boolean, isClickable: boolean, isDimmed = false) => ({
  display: 'flex',
  alignItems: 'center',
  height: 50,
  borderBottom: !isLast ? `1px solid ${theme.palette.divider}` : 'none',
  cursor: isClickable ? 'pointer' : 'default',
  opacity: isDimmed ? 0.5 : 1,
  paddingLeft: 2,
  paddingRight: 1,
  ...(isClickable && {
    '&:hover': {
      backgroundColor: theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .05)'
        : 'rgba(0, 0, 0, .03)',
    },
  }),
});

const SSOSingletonStrategiesContent = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const [editingStrategy, setEditingStrategy] = useState<StrategyType | null>(null);

  const data = useLazyLoadQuery<SSOSingletonStrategiesQuery>(ssoSingletonStrategiesQuery, {});
  const { settings } = data;

  const localEnabled = settings.local_auth?.enabled ?? false;
  const certEnabled = settings.cert_auth?.enabled ?? false;
  const headerEnabled = settings.headers_auth?.enabled ?? false;
  const isHttpsEnabled = settings.platform_https_enabled;

  const drawerTitles: Record<StrategyType, string> = {
    local: t_i18n('Local Authentication'),
    cert: t_i18n('Client Certificate Authentication'),
    header: t_i18n('HTTP Headers Authentication'),
  };

  return (
    <div style={{ marginBottom: 30 }}>
      <Card title={t_i18n('Authentication strategies')} padding="none">
        {/* Local Authentication */}
        <Box sx={rowSx(theme, false, true)} onClick={() => setEditingStrategy('local')}>
          <Box sx={{ flex: 1, display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
            <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
              {t_i18n('Local')}
            </Typography>
          </Box>
          <Box sx={{ width: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
            <ItemBoolean
              label={localEnabled ? t_i18n('Enabled') : t_i18n('Disabled')}
              status={localEnabled}
            />
          </Box>
          <Box sx={{ width: 40, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <IconButton size="small">
              <EditOutlined fontSize="small" />
            </IconButton>
          </Box>
        </Box>

        {/* HTTP Headers Authentication */}
        <Box sx={rowSx(theme, false, true)} onClick={() => setEditingStrategy('header')}>
          <Box sx={{ flex: 1, display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
            <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
              {t_i18n('HTTP headers')}
            </Typography>
          </Box>
          <Box sx={{ width: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
            <ItemBoolean
              label={headerEnabled && isEnterpriseEdition ? t_i18n('Enabled') : t_i18n('Disabled')}
              status={headerEnabled && isEnterpriseEdition}
            />
            {!isEnterpriseEdition && <span onClick={(e) => e.stopPropagation()}><EEChip /></span>}
          </Box>
          <Box sx={{ width: 40, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <IconButton size="small">
              <EditOutlined fontSize="small" />
            </IconButton>
          </Box>
        </Box>

        {/* Client Certificate Authentication */}
        <Box
          sx={rowSx(theme, true, !!isHttpsEnabled, !isHttpsEnabled)}
          onClick={() => isHttpsEnabled && setEditingStrategy('cert')}
        >
          <Box sx={{ flex: 1, display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
            <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
              {t_i18n('Client Certificate')}
            </Typography>
          </Box>
          <Box sx={{ width: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
            <ItemBoolean
              label={isHttpsEnabled && certEnabled && isEnterpriseEdition ? t_i18n('Enabled') : t_i18n('Disabled')}
              status={!!(isHttpsEnabled && certEnabled && isEnterpriseEdition)}
            />
            {!isEnterpriseEdition && isHttpsEnabled && <span onClick={(e) => e.stopPropagation()}><EEChip /></span>}
          </Box>
          <Box sx={{ width: 40, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {!isHttpsEnabled ? (
              <Tooltip title={t_i18n('Client certificate requires the platform to be configured with HTTPS')}>
                <span>
                  <IconButton size="small" disabled>
                    <InfoOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            ) : (
              <IconButton size="small">
                <EditOutlined fontSize="small" />
              </IconButton>
            )}
          </Box>
        </Box>
      </Card>

      {editingStrategy && (
        <Drawer title={drawerTitles[editingStrategy]} open={!!editingStrategy} onClose={() => setEditingStrategy(null)}>
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            {editingStrategy === 'local' && <LocalStrategyForm onCancel={() => setEditingStrategy(null)} />}
            {editingStrategy === 'cert' && <CertStrategyForm onCancel={() => setEditingStrategy(null)} />}
            {editingStrategy === 'header' && <HeaderStrategyForm onCancel={() => setEditingStrategy(null)} />}
          </Suspense>
        </Drawer>
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
