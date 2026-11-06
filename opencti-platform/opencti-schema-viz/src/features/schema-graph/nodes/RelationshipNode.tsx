import { Icon, Text } from '@filigran/design-system';
import { type CSSProperties, memo } from 'react';
import type { NodeProps } from 'reactflow';
import { typeColor } from '../../../shared/theme/typeAppearance';
import { clsx } from 'clsx';
import { useIsSelected } from '../hooks/useNodeExpansion';
import { useCompactMode } from '../hooks/useVisibleStats';
import { NodeHandles } from './NodeHandles';
import type { TypeNodeData } from './nodeData';
import './nodes.css';

/** A relationship type (uses, targets…) drawn as a pill, distinct from entity cards. */
const RelationshipNode = ({ data }: NodeProps<TypeNodeData>) => {
  const { type, role, direction, usageCount } = data;
  const selected = useIsSelected(type.id);
  const compact = useCompactMode();

  return (
    <div
      className={clsx('sv-node', 'sv-relationship-node', selected && 'is-selected', role === 'neighbor' && 'is-neighbor', type.isAbstract && 'is-abstract', compact && 'is-compact')}
      style={{ '--sv-type-color': typeColor(type) } as CSSProperties}
      title={type.label}
    >
      <NodeHandles direction={direction} />
      <Icon name="custom/relationship" size={16} className="sv-relationship-node__icon" />
      <span className="sv-node__label sv-mono">{type.label}</span>
      {!compact && usageCount > 0 && (
        <Text variant="content-caption" as="span" className="sv-faint" aria-label={`Allowed between ${usageCount} type pairs`}>{usageCount}</Text>
      )}
    </div>
  );
};

export default memo(RelationshipNode);
