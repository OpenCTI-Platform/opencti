import { Button, Icon, Text } from '@filigran/design-system';
import { type CSSProperties, memo } from 'react';
import type { NodeProps } from 'reactflow';
import { typeColor, typeIcon } from '../../../shared/theme/typeAppearance';
import { clsx } from 'clsx';
import { useIsSelected, useNodeExpansion } from '../hooks/useNodeExpansion';
import { useCompactMode } from '../hooks/useVisibleStats';
import { NodeHandles } from './NodeHandles';
import type { TypeNodeData } from './nodeData';
import './nodes.css';

const EntityNode = ({ data }: NodeProps<TypeNodeData>) => {
  const { type, role, direction, relationCount, onToggleExpand } = data;
  const selected = useIsSelected(type.id);
  const { isExpanded } = useNodeExpansion(type.id);
  const compact = useCompactMode();

  return (
    <div
      className={clsx('sv-node', 'sv-entity-node', selected && 'is-selected', role === 'neighbor' && 'is-neighbor', type.isAbstract && 'is-abstract', compact && 'is-compact')}
      style={{ '--sv-type-color': typeColor(type) } as CSSProperties}
      title={type.label}
    >
      <NodeHandles direction={direction} />
      <span className="sv-node__icon"><Icon name={typeIcon(type)} size={compact ? 24 : 20} /></span>
      <span className="sv-node__body">
        <span className="sv-node__label">{type.label}</span>
        {!compact && (
          <Text variant="content-caption" as="span" className="sv-node__meta sv-faint">
            {type.isAbstract ? `${type.category} · abstract` : type.category} · {type.attributes.length} attr.
          </Text>
        )}
      </span>
      {!compact && relationCount > 0 && (
        <Button
          size="sm"
          priority={isExpanded ? 'primary' : 'secondary'}
          startIcon={<Icon name={isExpanded ? 'minus' : 'plus'} size={16} />}
          className="nodrag"
          onClick={(event) => {
            event.stopPropagation();
            onToggleExpand(type.id);
          }}
          aria-pressed={isExpanded}
          aria-label={isExpanded ? `Hide relations of ${type.label}` : `Show ${relationCount} relations of ${type.label}`}
        >
          {relationCount}
        </Button>
      )}
    </div>
  );
};

export default memo(EntityNode);
