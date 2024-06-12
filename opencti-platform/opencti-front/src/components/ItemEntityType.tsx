import Chip from '@mui/material/Chip';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/material';
import { hexToRGB, itemColor } from '../utils/Colors';
import { useFormatter } from './i18n';
import useSchema from '../utils/hooks/useSchema';
import useHelper from '../utils/hooks/useHelper';
import ThemeLight from './ThemeLight';
import ThemeDark from './ThemeDark';
import ItemIcon from './ItemIcon';

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
  variant?: string;
  showIcon?: boolean;
  isRestricted?: boolean;
  styles?: React.CSSProperties;
}

const ItemEntityType: FunctionComponent<ItemEntityTypeProps> = ({
  variant = 'inList',
  entityType,
  showIcon = false,
  isRestricted = false,
  styles = {},
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const style = variant === 'inList' ? classes.chipInList : classes.chip;

  const { isRelationship: checkIsRelationship } = useSchema();
  const isRelationship = checkIsRelationship(entityType);

  const { palette: { mode } } = useTheme();
  const theme = mode === 'dark'
    ? ThemeDark()
    : ThemeLight();
  const { isFeatureEnable } = useHelper();
  const isMonochromeFeatureEnabled = isFeatureEnable('MONOCHROME_LABELS');
  const getStyle = () => {
    if (isRestricted) {
      const restrictedColor = itemColor('Restricted');
      return {
        backgroundColor: isMonochromeFeatureEnabled ? theme.palette.background.default : hexToRGB(restrictedColor),
        color: isMonochromeFeatureEnabled ? theme.palette.chip.main : restrictedColor,
        border: `1px solid ${restrictedColor}`,
      };
    }
    if (isMonochromeFeatureEnabled) {
      return {
        backgroundColor: theme.palette.background.default,
        color: isRelationship ? theme.palette.primary.main : theme.palette.chip.main,
        border: `1px solid ${isRelationship ? theme.palette.primary.main : itemColor(entityType)}`,
      };
    }
    return {
      backgroundColor: hexToRGB(itemColor(entityType), 0.08),
      color: isRelationship ? theme.palette.primary.main : itemColor(entityType),
      border: `1px solid ${isRelationship ? theme.palette.primary.main : itemColor(entityType)}`,
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
    return <></>;
  };
  const getLabel = () => {
    if (isRestricted) return t_i18n('Restricted');
    return t_i18n(isRelationship ? `relationship_${entityType}` : `entity_${entityType}`);
  };

  return (
    <Chip
      classes={{ root: style }}
      style={{
        ...styles,
        ...getStyle(),
      }}
      label={<>
        {getIcon()}
        {getLabel()}
      </>}
    />
  );
};

export default ItemEntityType;
