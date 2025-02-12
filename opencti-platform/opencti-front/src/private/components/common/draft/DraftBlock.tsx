import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import React, { FunctionComponent, ReactNode } from 'react';
import { getDraftModeColor } from './DraftChip';
import type { Theme } from '../../../../components/Theme';
import { hexToRGB } from '../../../../utils/Colors';
import { useFormatter } from '../../../../components/i18n';

interface DraftBlockProps {
  title?: string
  body?: ReactNode
  sx?: Record<string, React.CSSProperties>
}

const DraftBlock: FunctionComponent<DraftBlockProps> = ({ title, body, sx }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);

  return (
    <div
      style={{
        border: `1px solid ${hexToRGB(draftColor, 0.5)}`,
        color: draftColor,
        display: 'flex',
        flexDirection: 'column',
        minHeight: theme.spacing(4),
        maxHeight: theme.spacing(4.5),
        padding: theme.spacing(1),
        paddingTop: theme.spacing(0.5),
        borderRadius: theme.spacing(0.5),
        ...(sx?.root ?? {}),
      }}
    >
      <Typography
        variant="h4"
        style={{
          color: draftColor,
          marginTop: theme.spacing(-1.1),
          marginBottom: 0,
          background: theme.palette.background.default,
          paddingLeft: theme.spacing(1),
          paddingRight: theme.spacing(1),
          fontSize: 10,
          height: 10,
          textTransform: 'uppercase',
          fontFamily: '"Geologica", sans-serif',
          fontWeight: 700,
          width: 'fit-content',
          ...(sx?.title ?? {}),
        }}
      >
        {title ?? t_i18n('Draft Mode')}
      </Typography>
      <span style={{ overflow: 'hidden' }}>{body}</span>
    </div>
  );
};

export default DraftBlock;
