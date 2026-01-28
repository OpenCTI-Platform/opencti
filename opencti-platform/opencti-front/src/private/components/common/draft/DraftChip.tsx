import React from 'react';
import { useTheme } from '@mui/styles';
import { SimplePaletteColorOptions } from '@mui/material';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import Tag from '@common/tag/Tag';

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
