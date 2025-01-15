import React from 'react';
import { useTheme } from '@mui/styles';
import { SimplePaletteColorOptions } from '@mui/material';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

export const getDraftModeColor = (theme: Theme) => {
  return (theme.palette.warning as SimplePaletteColorOptions)?.main ?? theme.palette.primary.main;
};

export const DraftChip = ({ style }: { style?: React.CSSProperties }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);
  return (
    <div
      style={{
        fontSize: 'xx-small',
        textTransform: 'uppercase',
        fontWeight: 500,
        height: 14,
        display: 'inline-flex',
        justifyContent: 'center',
        alignItems: 'center',
        marginLeft: theme.spacing(0.5),
        padding: `${theme.spacing(1)} ${theme.spacing(0.5)}`,
        borderRadius: theme.borderRadius,
        border: `1px solid ${draftColor}`,
        color: draftColor,
        backgroundColor: 'transparent',
        ...style,
      }}
    >
      {t_i18n('Draft')}
    </div>
  );
};
