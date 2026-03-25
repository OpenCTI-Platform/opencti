import React, { FunctionComponent } from 'react';
import { itemColor } from '../utils/Colors';
import Tag from './common/tag/Tag';
import { useFormatter } from './i18n';
import ItemIcon from './ItemIcon';
import { useEntityTypeDisplayName } from '../utils/hooks/useEntityTypeDisplayName';

interface ItemEntityTypeProps {
  entityType: string;
  showIcon?: boolean;
  isRestricted?: boolean;
  maxWidth?: string;
}

const ItemEntityType: FunctionComponent<ItemEntityTypeProps> = ({
  entityType,
  showIcon = false,
  isRestricted = false,
  maxWidth,
}) => {
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();

  const isRelationship = t_i18n(`relationship_${entityType}`) !== `relationship_${entityType}`;

  const getIcon = () => {
    if (showIcon && !isRelationship) {
      return (
        <ItemIcon
          type={isRestricted ? 'Restricted' : entityType}
          size="small"
        />
      );
    }
    return null;
  };

  const getLabel = () => {
    if (isRestricted) return t_i18n('Restricted');
    if (isRelationship) return t_i18n(`relationship_${entityType}`);
    return entityLabel(entityType);
  };

  return (
    <Tag
      label={getLabel()}
      icon={getIcon() ?? undefined}
      color={isRestricted ? itemColor('Restricted') : itemColor(entityType)}
      maxWidth={maxWidth}
    />
  );
};

export default ItemEntityType;
