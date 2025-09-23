import React from 'react';
import { ArrowUpward, ArrowDownward, ArrowForward } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from './Theme';
import { useFormatter } from './i18n';

const inlineStyles = {
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
  },
  blueGrey: {
    backgroundColor: 'rgba(96, 125, 139, 0.08)',
    color: '#607d8b',
  },
};

interface ItemNumberDifferenceProps {
  value: number
  description: string
}

const NumberDifference = ({ value, description }: ItemNumberDifferenceProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  let color = inlineStyles.green;
  if (value < 0) color = inlineStyles.red;
  if (value === 0) color = inlineStyles.blueGrey;

  let Icon = ArrowUpward;
  if (value < 0) Icon = ArrowDownward;
  if (value === 0) Icon = ArrowForward;

  return (
    <div style={{
      ...color,
      fontSize: 12,
      display: 'flex',
      alignItems: 'center',
      padding: '2px 5px 2px 5px',
      gap: theme.spacing(0.25),
      borderRadius: 1,
      marginBottom: 4,
    }}
    >
      <Icon color="inherit" style={{ fontSize: 13 }} />
      <span>{value}</span>
      {description && (
        <span
          style={{
            fontSize: 9,
            color: theme.palette.text?.primary,
            paddingLeft: theme.spacing(0.5),
          }}
        >
          ({t_i18n(description)})
        </span>
      )}
    </div>
  );
};

export default NumberDifference;
