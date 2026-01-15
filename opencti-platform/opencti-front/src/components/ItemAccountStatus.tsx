import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import Tag from '@common/tag/Tag';

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
  const theme = useTheme<Theme>();
  const classes = useStyles();
  const style = classes.chip;
  const inlineStyles = {
    green: {
      backgroundColor: theme.palette.success.main,
      color: theme.palette.success.main,
      borderColor: theme.palette.success.main,
    },
    blue: {
      backgroundColor: theme.palette.severity?.info,
      color: theme.palette.severity?.info,
      borderColor: theme.palette.severity?.info,
    },
    red: {
      backgroundColor: theme.palette.error.main,
      color: theme.palette.error.main,
      borderColor: theme.palette.error.main,
    },
    orange: {
      backgroundColor: theme.palette.severity?.high,
      color: theme.palette.severity?.high,
      borderColor: theme.palette.severity?.high,
    },
    blueGrey: {
      backgroundColor: theme.palette.common.grey,
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
    <Tag
      classes={{ root: style }}
      variant={variant}
      label={label}
      style={classStyle}
    />
  );
};

export default ItemAccountStatus;
