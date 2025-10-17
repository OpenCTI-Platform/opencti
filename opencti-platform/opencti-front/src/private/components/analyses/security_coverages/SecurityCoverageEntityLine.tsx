import React from 'react';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircleOutlined, CircleOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DataColumns } from '../../../../components/list_lines';

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

interface SecurityCoverageEntityLineProps {
  dataColumns: DataColumns;
  node: any;
  onLabelClick: (key: string, value: string) => void;
  onToggleEntity: (entity: any) => void;
  selectedEntity: any | null;
}

const SecurityCoverageEntityLine: React.FC<SecurityCoverageEntityLineProps> = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  selectedEntity,
}) => {
  const classes = useStyles();
  const isSelected = selectedEntity?.id === node.id;
  
  return (
    <ListItemButton
      classes={{ root: classes.item }}
      divider={true}
      onClick={() => onToggleEntity(node)}
      selected={isSelected}
    >
      <ListItemIcon style={{ paddingLeft: 10 }}>
        {isSelected ? (
          <CheckCircleOutlined color="primary" />
        ) : (
          <CircleOutlined />
        )}
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={node.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              <ItemEntityType entityType={node.entity_type} />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.value.width }}
            >
              {getMainRepresentative(node)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {node.createdBy?.name ?? '-'}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={node.objectLabel || []}
                onClick={onLabelClick}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectMarking.width }}
            >
              <ItemMarkings
                variant="inList"
                markingDefinitions={node.objectMarking ?? []}
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
