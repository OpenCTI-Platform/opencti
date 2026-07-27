import React from 'react';
import { useTheme } from '@mui/styles';
import { SimplePaletteColorOptions } from '@mui/material';
import Chip from '@mui/material/Chip';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import Tag from '@common/tag/Tag';
import { hexToRGB } from '../../../../utils/Colors';

export const getDraftModeColor = (theme: Theme) => {
  return (theme.palette.warning as SimplePaletteColorOptions)?.main ?? theme.palette.primary.main;
};

export const DraftChip = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);

  return (
    <Tag
      label={t_i18n('Draft')}
      color={draftColor}
    />
  );
};

export const DraftStatusChip = ({ draftStatus }: { draftStatus?: string | null }) => {
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);
  const validatedColor = theme.palette.success.main;
  if (!draftStatus) return <div>-</div>;
  const color = draftStatus === 'open' ? draftColor : validatedColor;
  return (
    <Chip
      variant="outlined"
      label={draftStatus}
      style={{
        fontSize: 12,
        lineHeight: '12px',
        height: 20,
        float: 'left',
        textTransform: 'uppercase',
        borderRadius: 4,
        width: 90,
        color,
        borderColor: color,
        backgroundColor: hexToRGB(color),
      }}
    />
  );
};
