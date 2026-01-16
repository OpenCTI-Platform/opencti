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
}) => {
  const theme = useTheme<Theme>();

  const computeAccountStatusColor = (
    account_status: string | undefined | null,
  ) => {
    switch (account_status) {
      case 'Active':
        return theme.palette.severity.low;
      case 'Locked (security)':
        return theme.palette.common.grey;
      case 'Locked (training)':
        return theme.palette.common.grey;
      case 'Inactive':
        return theme.palette.severity.high;
      case 'Expired':
        return theme.palette.severity.critical;
      default:
        return theme.palette.common.grey;
    }
  };

  const color = computeAccountStatusColor(account_status);
  return (
    <Tag
      label={label}
      color={color}
    />
  );
};

export default ItemAccountStatus;
