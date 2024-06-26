import Chip from '@mui/material/Chip';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/material';
import { itemColor } from '../utils/Colors';
import { useFormatter } from './i18n';
import useSchema from '../utils/hooks/useSchema';
import ThemeLight from './ThemeLight';
import ThemeDark from './ThemeDark';
import ItemIcon from './ItemIcon';
import { truncate } from '../utils/String';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 120,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
}));

interface ItemEntityTypeProps {
  entityType: string;
  maxLength?: number;
  inList?: boolean;
  showIcon?: boolean;
  isRestricted?: boolean;
  style?: React.CSSProperties;
  size?: 'small' | 'medium' | 'large'
}

const ItemEntityType: FunctionComponent<ItemEntityTypeProps> = ({
  inList = true,
  maxLength,
  entityType,
  showIcon = false,
  isRestricted = false,
  style = {},
  size = 'medium',
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const rootStyle = inList ? classes.chipInList : classes.chip;

  const { isRelationship: checkIsRelationship } = useSchema();
  const isRelationship = checkIsRelationship(entityType);

  const { palette: { mode } } = useTheme();
  const theme = mode === 'dark'
    ? ThemeDark()
    : ThemeLight();
  const getStyle = () => {
    let width;
    switch (size) {
      case 'small':
        width = 100;
        break;
      case 'large':
        width = 140;
        break;
      case 'medium':
      default:
        width = 120;
    }
    if (isRestricted) {
      const restrictedColor = itemColor('Restricted');
      return {
        backgroundColor: theme.palette.background.default,
        color: theme.palette.chip.main,
        border: `1px solid ${restrictedColor}`,
        width,
      };
    }
    return {
      backgroundColor: theme.palette.background.default,
      color: isRelationship ? theme.palette.primary.main : theme.palette.chip.main,
      border: `1px solid ${isRelationship ? theme.palette.primary.main : itemColor(entityType)}`,
      width,
    };
  };
  const getIcon = () => {
    if (showIcon && !isRelationship) {
      return (
        <ItemIcon
          variant="inline"
          type={isRestricted ? 'restricted' : entityType}
        />
      );
    }
    return null;
  };
  const getLabel = () => {
    if (isRestricted) return t_i18n('Restricted');
    const label = t_i18n(isRelationship ? `relationship_${entityType}` : `entity_${entityType}`);
    if (maxLength) return truncate(label, maxLength);
    return label;
  };

  return (
    <Chip
      classes={{ root: rootStyle }}
      style={{
        ...getStyle(),
        ...style,
      }}
      label={<>
        {getIcon()}
        {getLabel()}
      </>}
    />
  );
};

export default ItemEntityType;
