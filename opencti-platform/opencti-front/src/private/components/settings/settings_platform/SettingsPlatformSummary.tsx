import { Chip } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import React, { ReactNode } from 'react';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import ItemCopy from '../../../../components/ItemCopy';
import type { Theme } from '../../../../components/Theme';
import EEChip from '../../common/entreprise_edition/EEChip';
import { countManagers, PlatformModule, toManagerItems } from '../settings_managers/settingsManagersUtils';

export interface PlatformAiStatus {
  label: string;
  tooltip: string;
  status: boolean;
}

interface SettingsPlatformSummaryProps {
  platformId: string;
  version: string;
  isEnterpriseEditionValid: boolean;
  instancesNumber: number;
  modules: ReadonlyArray<PlatformModule>;
  ai: PlatformAiStatus | null;
  action?: ReactNode;
}

interface Fact {
  key: string;
  label: ReactNode;
  value: ReactNode;
}

// Value line height: the 24 px of a chip, so text and chip values share one centre line.
const VALUE_HEIGHT = 24;

const SettingsPlatformSummary = ({
  platformId,
  version,
  isEnterpriseEditionValid,
  instancesNumber,
  modules,
  ai,
  action,
}: SettingsPlatformSummaryProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const managerCounts = countManagers(toManagerItems(modules, t_i18n, isEnterpriseEditionValid));

  const valueText = (text: string) => (
    <Typography variant="body1" sx={{ fontWeight: 500, lineHeight: `${VALUE_HEIGHT}px`, whiteSpace: 'nowrap' }}>{text}</Typography>
  );

  const facts: Fact[] = [
    { key: 'version', label: t_i18n('Version'), value: valueText(version) },
    {
      key: 'edition',
      label: t_i18n('Edition'),
      value: isEnterpriseEditionValid
        ? <Chip label={t_i18n('Enterprise')} severity="ee" />
        : <Chip label={t_i18n('Community')} />,
    },
    {
      key: 'architecture',
      label: t_i18n('Architecture mode'),
      value: valueText(instancesNumber > 1 ? t_i18n('Cluster') : t_i18n('Standalone')),
    },
    { key: 'nodes', label: t_i18n('Number of node(s)'), value: valueText(`${instancesNumber}`) },
    {
      key: 'managers',
      label: t_i18n('Managers'),
      value: valueText(t_i18n('{enabled} of {total} enabled', { values: { enabled: managerCounts.enabled, total: managerCounts.all } })),
    },
    ...(ai ? [{
      key: 'ai',
      label: <>{t_i18n('AI Powered')}<EEChip size="sm" /></>,
      value: <ItemBoolean label={ai.label} status={ai.status} tooltip={ai.tooltip} labelTextTransform="none" />,
    }] : []),
    {
      key: 'identifier',
      label: t_i18n('Platform identifier'),
      value: <ItemCopy content={platformId} variant="inLine" />,
    },
  ];

  return (
    <Card title={t_i18n('OpenCTI platform')} action={action} padding="medium" data-testid="settings-platform">
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', columnGap: 3, rowGap: 2 }}>
        {facts.map(({ key, label, value }) => (
          <Box key={key} data-testid={`settings-platform-${key}`} sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, minWidth: 0 }}>
            <Typography
              variant="body2"
              component="div"
              sx={{ display: 'flex', alignItems: 'center', height: 19, color: theme.palette.text.light, whiteSpace: 'nowrap' }}
            >
              {label}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', height: VALUE_HEIGHT }}>{value}</Box>
          </Box>
        ))}
      </Box>
    </Card>
  );
};

export default SettingsPlatformSummary;
