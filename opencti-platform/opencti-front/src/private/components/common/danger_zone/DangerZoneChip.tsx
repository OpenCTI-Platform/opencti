import React from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import Tag from '@common/tag/Tag';

interface DangerZoneChipProps {
  /** When true, the tooltip on the chip is suppressed. Useful inside MUI Menu
   *  items where competing tooltips cause hover glitches. */
  disableTooltip?: boolean;
}

const DangerZoneChip = ({ disableTooltip = false }: DangerZoneChipProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <Tag
      tooltipTitle={t_i18n('DangerZoneTooltip')}
      label={t_i18n('Danger Zone')}
      color={theme.palette.dangerZone.main}
      disableTooltip={disableTooltip}
    />
  );
};

export default DangerZoneChip;
