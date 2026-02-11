import { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import { useFormatter } from './i18n';
import Tag from './common/tag/Tag';

interface ItemOperationsProps {
  draftOperation?: string;
}

const ItemOperations: FunctionComponent<ItemOperationsProps> = ({ draftOperation }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const operationStylesLight = {
    green: theme.palette.designSystem.tertiary.green[800],
    red: theme.palette.designSystem.tertiary.red[700],
    yellow: theme.palette.designSystem.tertiary.yellow[400],
    lightYellow: theme.palette.designSystem.tertiary.orange[500],
  };
  const operationStylesDark = {
    green: theme.palette.designSystem.tertiary.green[800],
    red: theme.palette.designSystem.tertiary.red[700],
    yellow: theme.palette.designSystem.tertiary.yellow[400],
    lightYellow: theme.palette.designSystem.tertiary.orange[500],
  };

  const getChipColor = () => {
    switch (draftOperation) {
      case 'create':
        return theme.palette.mode === 'light'
          ? operationStylesLight.green
          : operationStylesDark.green;
      case 'update':
        return theme.palette.mode === 'light'
          ? operationStylesLight.yellow
          : operationStylesDark.yellow;
      case 'update_linked':
        return theme.palette.mode === 'light'
          ? operationStylesLight.lightYellow
          : operationStylesDark.lightYellow;
      case 'delete':
      case 'delete_linked':
        return theme.palette.mode === 'light'
          ? operationStylesLight.red
          : operationStylesDark.red;
      default:
        return undefined;
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
        return draftOperation ? t_i18n(draftOperation) : '';
    }
  };

  return (
    <Tag
      tooltipTitle={getChipTitle()}
      label={draftOperation}
      color={getChipColor()}
    />
  );
};

export default ItemOperations;
