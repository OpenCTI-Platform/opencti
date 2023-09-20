import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';

const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 150,
  },
}));

const inlineStyles = {
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  blue: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
  },
  orange: {
    backgroundColor: 'rgba(255, 152, 0, 0.08)',
    color: '#ff9800',
  },
  blueGrey: {
    backgroundColor: 'rgba(96, 125, 139, 0.08)',
    color: '#607d8b',
    fontStyle: 'italic',
  },
};

interface ItemAccountStatusProps {
  label: string;
  account_status?: string | null;
  variant?: 'outlined' | 'filled';
}

const computeAccountStatusStyle = (account_status: string | undefined | null) => {
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
  const classes = useStyles();
  const style = classes.chip;
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
