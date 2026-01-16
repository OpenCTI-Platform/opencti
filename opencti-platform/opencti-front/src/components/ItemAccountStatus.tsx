import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import Tag from '@common/tag/Tag';

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
  const inlineStyles = {
    green: {
      backgroundColor: theme.palette.severity.low,
      color: theme.palette.severity.low,
      borderColor: theme.palette.severity.low,
    },
    blue: {
      backgroundColor: theme.palette.severity.info,
      color: theme.palette.severity.info,
      borderColor: theme.palette.severity.info,
    },
    red: {
      backgroundColor: theme.palette.severity.critical,
      color: theme.palette.severity.critical,
      borderColor: theme.palette.severity.critical,
    },
    orange: {
      backgroundColor: theme.palette.severity.high,
      color: theme.palette.severity.high,
      borderColor: theme.palette.severity.high,
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
      variant={variant}
      label={label}
      style={classStyle}
    />
  );
};

export default ItemAccountStatus;
