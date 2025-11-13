import React from 'react';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary?.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
}));

interface EntityNode {
  id: string;
  entity_type: string;
  representative?: { main?: string };
  createdBy?: { name?: string };
  objectLabel?: Array<{ value: string; color: string; id: string; }>;
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
  const classes = useStyles();
  // Handle both edge.node and direct node structures
  const entity = 'node' in node && node.node ? node.node : node as EntityNode;
  const isSelected = selectedEntity?.id === entity.id;

  return (
    <ListItemButton
      classes={{ root: classes.item }}
      divider={true}
      onClick={() => onToggleEntity(entity)}
      selected={isSelected}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={entity.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              <ItemEntityType entityType={entity.entity_type} />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.value.width }}
            >
              {getMainRepresentative(entity)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {entity.createdBy?.name ?? '-'}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={entity.objectLabel || []}
                onClick={onLabelClick}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectMarking.width }}
            >
              <ItemMarkings
                variant="inList"
                markingDefinitions={entity.objectMarking ?? []}
                limit={1}
              />
            </div>
          </div>
        }
      />
    </ListItemButton>
  );
};

export default SecurityCoverageEntityLine;
