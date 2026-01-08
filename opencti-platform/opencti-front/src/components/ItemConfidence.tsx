import React, { FunctionComponent } from 'react';
import { useLevel } from '../utils/hooks/useScale';
import Tag from '@common/tag/Tag';

interface ItemConfidenceProps {
  confidence: number | null | undefined;
  entityType: string;
}

const ItemConfidence: FunctionComponent<ItemConfidenceProps> = ({ confidence, entityType }) => {
  const { level: confidenceLevel } = useLevel(entityType, 'confidence', confidence);

  return (
    <Tag
      label={confidenceLevel.label}
      color={confidenceLevel.color}
    />
  );
};

export default ItemConfidence;
