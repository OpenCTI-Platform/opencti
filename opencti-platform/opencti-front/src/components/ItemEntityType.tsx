import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/material';
import { itemColor } from '../utils/Colors';
import { useFormatter } from './i18n';
import ThemeLight from './ThemeLight';
import ThemeDark from './ThemeDark';
import ItemIcon from './ItemIcon';
import { chipInListBasicStyle } from '../utils/chipStyle';
import { Chip, Tooltip } from '@components';

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
    ...chipInListBasicStyle,
    width: 120,
    textTransform: 'uppercase',
  },
}));

interface ItemEntityTypeProps {
  entityType: string;
  inList?: boolean;
  showIcon?: boolean;
  isRestricted?: boolean;
  style?: React.CSSProperties;
  size?: 'small' | 'medium' | 'large'
}

const ItemEntityType: FunctionComponent<ItemEntityTypeProps> = ({
  inList = true,
  entityType,
  showIcon = false,
  isRestricted = false,
  style = {},
  size = 'medium',
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const rootStyle = inList ? classes.chipInList : classes.chip;

  const isRelationship = t_i18n(`relationship_${entityType}`) !== `relationship_${entityType}`;

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
          type={isRestricted ? 'Restricted' : entityType}
        />
      );
    }
    return null;
  };
  const getLabel = () => {
    if (isRestricted) return t_i18n('Restricted');
    return t_i18n(isRelationship ? `relationship_${entityType}` : `entity_${entityType}`);
  };

  return (
    <Tooltip title={getLabel()}>
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
    </Tooltip>
  );
};

export default ItemEntityType;
