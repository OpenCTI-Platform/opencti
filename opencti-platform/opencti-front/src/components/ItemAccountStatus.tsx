import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/material';
import useAuth from '../utils/hooks/useAuth';
import ThemeDark from './ThemeDark';
import ThemeLight from './ThemeLight';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    marginRight: 7,
    borderRadius: 4,
    width: 150,
  },
}));

const inlineStyles = {
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
    borderColor: '#4caf50',
  },
  blue: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
    borderColor: '#5c7bf5',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
    borderColor: '#f44336',
  },
  orange: {
    backgroundColor: 'rgba(255, 152, 0, 0.08)',
    color: '#ff9800',
    borderColor: '#ff9800',
  },
  blueGrey: {
    backgroundColor: 'rgba(96, 125, 139, 0.08)',
    color: '#607d8b',
    borderColor: '#607d8b',
    fontStyle: 'italic',
  },
};

interface ItemAccountStatusProps {
  label: string;
  account_status?: string | null;
  variant?: 'outlined' | 'filled';
}

const computeAccountStatusStyle = (
  account_status: string | undefined | null,
) => {
  switch (account_status) {
    case 'Active':
      return inlineStyles.green;
    case 'Locked (security)':
      return inlineStyles.blueGrey;
    case 'Locked (training)':
      return inlineStyles.blueGrey;
    case 'Inactive':
      return inlineStyles.orange;
    case 'Expired':
      return inlineStyles.red;
    default:
      return inlineStyles.blueGrey;
  }
};

const ItemAccountStatus: FunctionComponent<ItemAccountStatusProps> = ({
  label,
  account_status,
  variant,
}) => {
  const { me: { monochrome_labels } } = useAuth();
  const { palette: { mode } } = useTheme();
  const theme = mode === 'dark'
    ? ThemeDark()
    : ThemeLight();
  const classes = useStyles();
  const style = classes.chip;
  const classStyle = computeAccountStatusStyle(account_status);
  return (
    <Chip
      classes={{ root: style }}
      variant={variant}
      label={label}
      style={{
        ...classStyle,
        color: theme.palette.chip.main,
        borderColor: monochrome_labels ? theme.palette.background.accent : classStyle.borderColor,
        background: monochrome_labels ? theme.palette.background.accent : classStyle.backgroundColor,
      }}
    />
  );
};

export default ItemAccountStatus;
