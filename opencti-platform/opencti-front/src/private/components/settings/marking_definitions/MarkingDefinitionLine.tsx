import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import makeStyles from '@mui/styles/makeStyles';
import { MarkingDefinitionLine_node$data } from '@components/settings/marking_definitions/__generated__/MarkingDefinitionLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import MarkingDefinitionPopover from './MarkingDefinitionPopover';
import ItemIcon from '../../../../components/ItemIcon';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles < Theme >((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
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
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

interface MarkingDefinitionLineProps {
  dataColumns: DataColumns
  node: MarkingDefinitionLine_node$data
}

const MarkingDefinitionLineComponent: React.FC<MarkingDefinitionLineProps> = (props) => {
  const classes = useStyles();

  const { fd } = useFormatter();
  const { dataColumns, node } = props;
  const { isSensitive, isAllowed } = useSensitiveModifications(node.standard_id);

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
    >
      <ListItemIcon>
        <ItemIcon type="Marking-Definition" color={node.x_opencti_color} />
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.definition_type.width, display: 'flex', alignItems: 'center' }}
            >
              {node.definition_type}{isSensitive && <DangerZoneChip />}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.definition.width }}
            >
              {node.definition}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.x_opencti_color.width }}
            >
              {node.x_opencti_color}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.x_opencti_order.width }}
            >
              {node.x_opencti_order}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created.width }}
            >
              {fd(node.created)}
            </div>
          </>
          }
      />
      <ListItemSecondaryAction>
        <MarkingDefinitionPopover
          markingDefinitionId={node.id}
          disabled={!isAllowed}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const MarkingDefinitionLine = createFragmentContainer(MarkingDefinitionLineComponent, {
  node: graphql`
    fragment MarkingDefinitionLine_node on MarkingDefinition {
      id
      standard_id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
      created
      modified
    }
  `,
});

export const MarkingDefinitionLineDummy: React.FC<Pick<MarkingDefinitionLineProps, 'dataColumns'>> = ({ dataColumns }) => {
  const classes = useStyles();

  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.definition_type.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.definition.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.x_opencti_color.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.x_opencti_order.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
          </div>
          }
      />
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <MoreVert />
      </ListItemSecondaryAction>
    </ListItem>
  );
};
