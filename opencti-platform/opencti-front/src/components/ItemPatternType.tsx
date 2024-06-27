import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/material';
import ThemeDark from './ThemeDark';
import ThemeLight from './ThemeLight';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 15,
    lineHeight: '18px',
    height: 30,
    margin: '0 7px 7px 0',
    borderRadius: 4,
    width: 130,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    marginRight: 7,
    borderRadius: 4,
    width: 80,
  },
}));

interface InlineStyle {
  [k: string]: {
    backgroundColor: string;
    color: string;
    border: string;
  };
}

const inlineStyles: InlineStyle = {
  stix: {
    backgroundColor: 'rgba(32, 58, 246, 0.08)',
    color: '#203af6',
    border: '1px solid #203af6',
  },
  pcre: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
    border: '1px solid #5c7bf5',
  },
  sigma: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
    border: '1px solid #4caf50',
  },
  snort: {
    backgroundColor: 'rgb(231, 133, 109, 0.08)',
    color: '#8d4e41',
    border: '1px solid #4e342e',
  },
  suricata: {
    backgroundColor: 'rgba(0, 105, 92, 0.08)',
    color: '#00695c',
    border: '1px solid #00695c',
  },
  yara: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
    border: '1px solid #f44336',
  },
  'tanium-signal': {
    backgroundColor: 'rgba(243, 25, 25, 0.08)',
    color: '#f31919',
    border: '1px solid #f31919',
  },
  spl: {
    backgroundColor: 'rgba(239, 108, 0, 0.08)',
    color: '#ef6c00',
    border: '1px solid #ef6c00',
  },
  eql: {
    backgroundColor: 'rgba(32, 201, 151, 0.10)',
    color: '#007bff',
    border: '1px solid #007bff',
  },
  shodan: {
    backgroundColor: 'rgb(185, 52, 37, 0.08)',
    color: '#b93425',
    border: '1px solid #b93425',
  },
};

interface ItemPatternTypeProps {
  label: string;
  variant?: 'inList';
}

const ItemPatternType: FunctionComponent<ItemPatternTypeProps> = ({
  variant,
  label,
}) => {
  const classes = useStyles();
  const className = variant === 'inList' ? classes.chipInList : classes.chip;
  const { palette: { mode } } = useTheme();
  const theme = mode === 'dark'
    ? ThemeDark()
    : ThemeLight();
  const hasPredefinedStyle = Object.keys(inlineStyles).includes(label);
  let style: React.CSSProperties = hasPredefinedStyle
    ? inlineStyles[label]
    : inlineStyles.stix;
  style = {
    ...style,
    backgroundColor: theme.palette.background.default,
    color: theme.palette.chip.main,
  };
  return (
    <Chip
      className={className}
      style={style}
      label={label}
    />
  );
};
export default ItemPatternType;
