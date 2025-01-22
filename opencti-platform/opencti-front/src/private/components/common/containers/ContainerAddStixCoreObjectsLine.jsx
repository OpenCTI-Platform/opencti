import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { CheckCircleOutlined, CircleOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { DraftChip } from '../draft/DraftChip';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemEntityType from '../../../../components/ItemEntityType';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
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
    color: theme.palette.grey[700],
  },
}));

const ContainerAddStixCoreObjectsLineComponent = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  addedElements,
}) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      onClick={(event) => onToggleEntity(node, event)}
    >
      <ListItemIcon style={{ paddingLeft: 10 }}>
        {node.id in (addedElements || {}) ? (
          <CheckCircleOutlined
            classes={{ root: classes.icon }}
            color="primary"
          />
        ) : (
          <CircleOutlined classes={{ root: classes.icon }} />
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
              {node.draftVersion && (<DraftChip/>)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {R.pathOr('', ['createdBy', 'name'], node)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={node.objectLabel}
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
    </ListItem>
  );
};

export const ContainerAddStixCoreObjectsLine = createFragmentContainer(
  ContainerAddStixCoreObjectsLineComponent,
  {
    node: graphql`
      fragment ContainerAddStixCoreObjectsLine_node on StixCoreObject {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        standard_id
        parent_types
        entity_type
        representative {
          main
        }
        created_at
        ... on AttackPattern {
          name
        }
        ... on Campaign {
          name
        }
        ... on Note {
          attribute_abstract
        }
        ... on ObservedData {
          name
        }
        ... on Opinion {
          opinion
        }
        ... on Report {
          name
        }
        ... on Grouping {
          name
        }
        ... on CourseOfAction {
          name
        }
        ... on Individual {
          name
        }
        ... on Organization {
          name
        }
        ... on Sector {
          name
        }
        ... on System {
          name
        }
        ... on Indicator {
          name
        }
        ... on Infrastructure {
          name
        }
        ... on IntrusionSet {
          name
        }
        ... on Position {
          name
        }
        ... on City {
          name
        }
        ... on AdministrativeArea {
          name
        }
        ... on Country {
          name
        }
        ... on Region {
          name
        }
        ... on Malware {
          name
        }
        ... on MalwareAnalysis {
          result_name
        }
        ... on ThreatActor {
          name
        }
        ... on Tool {
          name
        }
        ... on Vulnerability {
          name
        }
        ... on Incident {
          name
        }
        ... on Event {
          name
        }
        ... on Channel {
          name
        }
        ... on Narrative {
          name
        }
        ... on Language {
          name
        }
        ... on DataComponent {
          name
        }
        ... on DataSource {
          name
        }
        ... on Case {
          name
        }
        ... on StixCyberObservable {
          observable_value
          ... on StixFile {
            hashes {
              algorithm
              hash
            }
          }
        }
        createdBy {
          id
          entity_type
          ... on Identity {
            name
          }
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        objectLabel {
          id
          value
          color
        }
        creators {
          id
          name
        }
      }
    `,
  },
);

export const ContainerAddStixCoreObjecstLineDummy = ({ dataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      style={{ minWidth: 40 }}
    >
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <CircleOutlined />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
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
              style={{ width: dataColumns.value.width }}
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
              style={{ width: dataColumns.createdBy.width }}
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
              style={{ width: dataColumns.objectLabel.width }}
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
              style={{ width: dataColumns.objectMarking.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={100}
                height="100%"
              />
            </div>
          </div>
        }
      />
    </ListItem>
  );
};
