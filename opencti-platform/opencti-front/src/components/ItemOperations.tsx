import Chip from '@mui/material/Chip';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';

const useStyles = makeStyles(() => ({
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    marginRight: 7,
    borderRadius: 4,
    width: 90,
    textTransform: 'uppercase',
  },
}));

interface ItemOperationsProps {
  draftOperation: string
}

const operationStylesLight = {
  green: {
    backgroundColor: '#2e7d32',
    color: '#ffffff',
  },
  red: {
    backgroundColor: '#c62828',
    color: '#ffffff',
  },
  yellow: {
    backgroundColor: '#ff9800',
    color: '#ffffff',
  },
  lightYellow: {
    backgroundColor: '#ec7629',
    color: '#ffffff',
  },
};

const operationStylesDark = {
  green: {
    backgroundColor: '#2e7d32',
  },
  red: {
    backgroundColor: '#c62828',
  },
  yellow: {
    backgroundColor: '#ff9800',
  },
  lightYellow: {
    backgroundColor: '#ec7629',
  },
};

const ItemOperations: FunctionComponent<ItemOperationsProps> = ({ draftOperation }) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();

  const getChipStyle = () => {
    switch (draftOperation) {
      case 'create':
        return theme.palette.mode === 'light'
          ? { ...operationStylesLight.green }
          : { ...operationStylesDark.green };
      case 'update':
        return theme.palette.mode === 'light'
          ? { ...operationStylesLight.yellow }
          : { ...operationStylesDark.yellow };
      case 'update_linked':
        return theme.palette.mode === 'light'
          ? { ...operationStylesLight.lightYellow }
          : { ...operationStylesDark.lightYellow };
      case 'delete':
        return theme.palette.mode === 'light'
          ? { ...operationStylesLight.red }
          : { ...operationStylesDark.red };
      default:
        return {};
    }
  };
  return (
    <Chip
      title={draftOperation}
      label={draftOperation}
      classes={{ root: classes.chipInList }}
      variant="outlined"
      style={getChipStyle()}
    />
  );
};

export default ItemOperations;
