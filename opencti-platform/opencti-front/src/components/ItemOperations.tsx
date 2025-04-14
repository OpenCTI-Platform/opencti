import Chip from '@mui/material/Chip';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import { useFormatter } from './i18n';

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
  const { t_i18n } = useFormatter();

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
      case 'delete_linked':
        return theme.palette.mode === 'light'
          ? { ...operationStylesLight.red }
          : { ...operationStylesDark.red };
      default:
        return {};
    }
  };

  const getChipTitle = () => {
    switch (draftOperation) {
      case 'create':
        return t_i18n('does not exist in the main knowledge base');
      case 'update':
        return t_i18n('existed in main knowledge, modified in the draft');
      case 'update_linked':
        return t_i18n('impacted by a modification to a linked entity (relation, added in container...)');
      case 'delete':
        return t_i18n('existed in main knowledge base, deleted in draft');
      case 'delete_linked':
        return t_i18n('deleted as a result of the deletion of a linked entity');
      default:
        return t_i18n(draftOperation);
    }
  };

  return (
    <Chip
      title={getChipTitle()}
      label={draftOperation}
      classes={{ root: classes.chipInList }}
      variant="outlined"
      style={getChipStyle()}
    />
  );
};

export default ItemOperations;
