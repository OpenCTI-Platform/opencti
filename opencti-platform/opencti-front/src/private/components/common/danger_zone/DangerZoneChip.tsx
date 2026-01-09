import React from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import Tag from '@common/tag/Tag';

const DangerZoneChip = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <Tag
      tooltipTitle={t_i18n('DangerZoneTooltip')}
      label={t_i18n('Danger Zone')}
      color={theme.palette.dangerZone.main}
    />
  );
};

export default DangerZoneChip;
