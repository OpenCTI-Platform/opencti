import { Button, Chip, Icon, Text } from '@filigran/design-system';
import { memo } from 'react';
import type { NodeProps } from 'reactflow';
import { useSchemaGraphStore } from '../../../state/schemaGraphStore';
import { entityFamily } from '../../../shared/theme/typeAppearance';
import { clsx } from 'clsx';
import { NodeHandles } from './NodeHandles';
import type { TargetGroupNodeData } from './nodeData';
import { GROUP_MAX_ITEMS } from './nodeSizes';
import './nodes.css';

/** Counterparts of an expanded relation that are not on the canvas yet. Clicking one brings it in. */
const TargetGroupNode = ({ data }: NodeProps<TargetGroupNodeData>) => {
  const { group, direction, onReveal } = data;
  const types = useSchemaGraphStore((state) => state.schema?.types);
  const shown = group.typeIds.slice(0, GROUP_MAX_ITEMS);
  const hiddenCount = group.typeIds.length - shown.length;
  const noun = group.direction === 'out' ? 'target' : 'source';

  return (
    <div className={clsx('sv-node', 'sv-group-node', group.relationKind === 'ref' && 'is-ref')}>
      <NodeHandles direction={direction} />
      <div className="sv-group-node__header">
        <Icon name={group.direction === 'out' ? 'arrow-right' : 'arrow-left'} size={16} className="sv-faint" />
        <Text variant="content-code" as="span" className="sv-group-node__relation">{group.relationName}</Text>
        <Button
          priority="tertiary"
          size="sm"
          className="nodrag"
          onClick={(event) => {
            event.stopPropagation();
            onReveal(group.typeIds);
          }}
          aria-label={`Add all ${group.typeIds.length} ${noun}s to the canvas`}
        >
          {`${group.typeIds.length} ${noun}s`}
        </Button>
      </div>
      <ul className="sv-group-node__items">
        {shown.map((typeId) => {
          const type = types?.get(typeId);
          const family = type ? entityFamily(type) : undefined;
          return (
            <li key={typeId}>
              <Chip
                label={type?.label ?? typeId}
                {...(family ? { entity: family } : { severity: 'neutral' as const })}
                startIcon={<Icon name="plus" size={16} />}
                className="nodrag"
                onClick={(event) => {
                  event.stopPropagation();
                  onReveal([typeId]);
                }}
                aria-label={`Add ${type?.label ?? typeId} to the canvas`}
              />
            </li>
          );
        })}
        {hiddenCount > 0 && (
          <li>
            <Chip
              label={`+${hiddenCount} more, add all`}
              severity="neutral"
              className="nodrag"
              onClick={(event) => {
                event.stopPropagation();
                onReveal(group.typeIds);
              }}
            />
          </li>
        )}
      </ul>
    </div>
  );
};

export default memo(TargetGroupNode);
