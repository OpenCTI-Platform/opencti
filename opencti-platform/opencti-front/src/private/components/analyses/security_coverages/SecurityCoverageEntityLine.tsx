import React from 'react';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { styled } from '@mui/material/styles';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface EntityNode {
  id: string;
  entity_type: string;
  representative?: { main?: string };
  createdBy?: { name?: string };
  objectLabel?: Array<{ value: string; color: string; id: string }>;
  objectMarking?: Array<{ id: string; definition_type: string; definition: string }>;
}

interface SecurityCoverageEntityLineProps {
  dataColumns: DataColumns;
  node: { node?: EntityNode } | EntityNode;
  onLabelClick: HandleAddFilter;
  onToggleEntity: (entity: EntityNode) => void;
  selectedEntity: EntityNode | null;
}

const SecurityCoverageEntityLine: React.FC<SecurityCoverageEntityLineProps> = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  selectedEntity,
}) => {
  // Handle both edge.node and direct node structures
  const entity = 'node' in node && node.node ? node.node : node as EntityNode;
  const isSelected = selectedEntity?.id === entity.id;

  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      onClick={() => onToggleEntity(entity)}
      selected={isSelected}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <ItemIcon type={entity.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.entity_type.width }}
            >
              <ItemEntityType entityType={entity.entity_type} />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.value.width }}
            >
              {getMainRepresentative(entity)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.createdBy.width }}
            >
              {entity.createdBy?.name ?? EMPTY_VALUE}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={entity.objectLabel || []}
                onClick={onLabelClick}
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.objectMarking.width }}
            >
              <ItemMarkings
                markingDefinitions={entity.objectMarking ?? []}
                limit={1}
              />
            </BodyItem>
          </div>
        )}
      />
    </ListItemButton>
  );
};

export default SecurityCoverageEntityLine;
