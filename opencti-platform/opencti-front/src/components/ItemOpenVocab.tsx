import React, { FunctionComponent, Suspense } from 'react';
import { InformationOutline } from 'mdi-material-ui';
import ItemSeverity from './ItemSeverity';
import ItemPriority from './ItemPriority';
import Tag from '@common/tag/Tag';
import { EMPTY_VALUE } from '../utils/String';
import { useFormatter } from './i18n';
import useVocabularyEntries from '../utils/hooks/useVocabularyEntries';
import { vocabularyValueLabel } from '../utils/vocabulary/vocabularyDisplay';

interface ItemOpenVocabProps {
  type: string;
  value?: string | null;
  small?: boolean;
  hideEmpty?: boolean;
  displayMode?: 'chip' | 'span';
  // Shows the translated human label (AI agent, Very high) instead of the stored key (AI_AGENT, VERY_HIGH)
  humanLabel?: boolean;
  icon?: React.ReactElement;
}

interface VocabTagProps {
  type: string;
  value: string;
  humanLabel: boolean;
  icon?: React.ReactElement;
}

// The tag of a value without its vocabulary entry: the fallback while the entries load, and the tag of a value no entry holds
const PlainVocabTag: FunctionComponent<VocabTagProps> = ({ value, humanLabel, icon }) => {
  const { t_i18n } = useFormatter();
  const label = humanLabel ? vocabularyValueLabel(value, t_i18n) : value;
  return <Tag label={label} icon={icon} labelTextTransform={humanLabel ? 'none' : undefined} />;
};

// The tag of a value in the colour its vocabulary entry carries, with the entry's description as tooltip
const ColoredVocabTag: FunctionComponent<VocabTagProps> = ({ type, value, humanLabel, icon }) => {
  const { t_i18n } = useFormatter();
  const entry = useVocabularyEntries(type).get(value);
  const label = humanLabel ? vocabularyValueLabel(value, t_i18n) : value;
  return (
    <Tag
      label={label}
      color={entry?.color}
      icon={icon}
      tooltipTitle={entry?.description ? t_i18n(entry.description) : undefined}
      labelTextTransform={humanLabel ? 'none' : undefined}
    />
  );
};

const ItemOpenVocab: FunctionComponent<ItemOpenVocabProps> = ({
  type,
  value,
  small = true,
  hideEmpty = true,
  displayMode = 'span',
  humanLabel = false,
  icon,
}) => {
  if (!value) {
    return <>{EMPTY_VALUE}</>;
  }

  let tag = (
    <PlainVocabTag type={type} value={value} humanLabel={humanLabel} icon={icon} />
  );

  if (displayMode === 'chip') {
    if (type === 'case_severity_ov' || type === 'incident_severity_ov') {
      tag = <ItemSeverity label={value} severity={value} />;
    } else if (type === 'case_priority_ov') {
      tag = <ItemPriority label={value} priority={value} />;
    } else {
      // Every other vocabulary takes the colour of its entry when it has one (seeded or set in Settings > Taxonomies > Vocabularies)
      tag = (
        <Suspense fallback={tag}>
          <ColoredVocabTag type={type} value={value} humanLabel={humanLabel} icon={icon} />
        </Suspense>
      );
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
