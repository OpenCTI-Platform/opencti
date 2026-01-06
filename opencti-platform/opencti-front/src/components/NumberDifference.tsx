import React from 'react';
import { ArrowUpward, ArrowDownward, ArrowForward } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from './Theme';
import { useFormatter } from './i18n';

const inlineStyles = {
  green: {
    color: '#4caf50',
  },
  red: {
    color: '#f44336',
  },
  blueGrey: {
    color: '#607d8b',
  },
};

interface ItemNumberDifferenceProps {
  value: number;
  description: string;
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
      gap: theme.spacing(0.25),
    }}
    >
      <Icon color="inherit" style={{ fontSize: 13 }} />
      <span>{value}</span>
      {description && (
        <span>
          ({t_i18n(description)})
        </span>
      )}
    </div>
  );
};

export default NumberDifference;
