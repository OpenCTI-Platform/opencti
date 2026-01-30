import React, { FunctionComponent } from 'react';
import { InformationOutline } from 'mdi-material-ui';
import ItemSeverity from './ItemSeverity';
import ItemPriority from './ItemPriority';
import Tag from '@common/tag/Tag';

interface ItemOpenVocabProps {
  type: string;
  value?: string | null;
  small?: boolean;
  hideEmpty?: boolean;
  displayMode?: 'chip' | 'span';
}

const ItemOpenVocab: FunctionComponent<ItemOpenVocabProps> = ({
  type,
  value,
  small = true,
  hideEmpty = true,
  displayMode = 'span',
}) => {
  if (!value) {
    return <>-</>;
  }

  let tag = (
    <Tag label={value} />
  );

  if (displayMode === 'chip') {
    if (type === 'case_severity_ov' || type === 'incident_severity_ov') {
      tag = <ItemSeverity label={value} severity={value} />;
    } else if (type === 'case_priority_ov') {
      tag = <ItemPriority label={value} priority={value} />;
    }
    return hideEmpty ? (
      tag
    ) : (
      <span>{tag}</span>
    );
  }

  return (
    <span
      style={{
        margin: 0,
        padding: 0,
        display: 'flex',
      }}
    >
      {tag}
      {hideEmpty ? '' : (
        <InformationOutline
          style={small
            ? { margin: '5px 0 0 10px' }
            : { margin: '15px 0 0 10px' }
          }
          fontSize="small"
          color="secondary"
        />
      )}
    </span>
  );
};

export default ItemOpenVocab;
