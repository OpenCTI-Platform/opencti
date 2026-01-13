import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { alpha, useTheme } from '@mui/material';

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

interface ItemAccountStatusProps {
  label: string;
  account_status?: string | null;
  variant?: 'outlined' | 'filled';
}

const ItemAccountStatus: FunctionComponent<ItemAccountStatusProps> = ({
  label,
  account_status,
  variant,
}) => {
  const theme = useTheme();
  const classes = useStyles();
  const style = classes.chip;
  const inlineStyles = {
    green: {
      backgroundColor: alpha(theme.palette.success.main, 0.08),
      color: theme.palette.success.main,
      borderColor: theme.palette.success.main,
    },
    blue: {
      backgroundColor: alpha(theme.palette.severity?.info || '#4DCCFF', 0.08),
      color: theme.palette.severity?.info || '#4DCCFF',
      borderColor: theme.palette.severity?.info || '#4DCCFF',
    },
    red: {
      backgroundColor: alpha(theme.palette.error.main, 0.08),
      color: theme.palette.error.main,
      borderColor: theme.palette.error.main,
    },
    orange: {
      backgroundColor: alpha(theme.palette.severity?.high || '#E6700F', 0.08),
      color: theme.palette.severity?.high || '#E6700F',
      borderColor: theme.palette.severity?.high || '#E6700F',
    },
    blueGrey: {
      backgroundColor: alpha(theme.palette.common.grey, 0.08),
      color: theme.palette.common.grey,
      borderColor: theme.palette.common.grey,
      fontStyle: 'italic',
    },
  };

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

  const classStyle = computeAccountStatusStyle(account_status);
  return (
    <Chip
      classes={{ root: style }}
      variant={variant}
      label={label}
      style={classStyle}
    />
  );
};

export default ItemAccountStatus;
