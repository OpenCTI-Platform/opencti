import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { CheckCircleOutlined, CircleOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { InvestigationAddStixCoreObjectsLine_node$data } from '@components/workspaces/investigations/__generated__/InvestigationAddStixCoreObjectsLine_node.graphql';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import ItemEntityType from '../../../../components/ItemEntityType';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
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
    color: theme.palette.grey?.[700],
  },
}));

interface InvestigationAddStixCoreObjectsLineComponentProps {
  dataColumns: DataColumns
  node: InvestigationAddStixCoreObjectsLine_node$data,
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void,
  onToggleEntity: (
    entity: InvestigationAddStixCoreObjectsLine_node$data,
    event: React.SyntheticEvent
  ) => void,
  addedElements: {
    [key:string]: InvestigationAddStixCoreObjectsLine_node$data
  },
}

const InvestigationAddStixCoreObjectsLineComponent = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  addedElements,
}: InvestigationAddStixCoreObjectsLineComponentProps) => {
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
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {node.createdBy?.name}
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
                markingDefinitions={(node.objectMarking ?? [])}
                limit={1}
              />
            </div>
          </div>
        }
      />
    </ListItem>
  );
};

export const InvestigationAddStixCoreObjectsLine = createFragmentContainer(
  InvestigationAddStixCoreObjectsLineComponent,
  {
    node: graphql`
      fragment InvestigationAddStixCoreObjectsLine_node on StixCoreObject {
        id
        standard_id
        parent_types
        entity_type
        created_at
        numberOfConnectedElement
        ... on StixDomainObject {
          created
        }
        ... on AttackPattern {
          name
          description
          x_mitre_id
        }
        ... on Campaign {
          name
          description
          first_seen
          last_seen
        }
        ... on Channel {
          name
        }
        ... on Note {
          attribute_abstract
          content
        }
        ... on ObservedData {
          name
          first_observed
          last_observed
        }
        ... on Opinion {
          opinion
        }
        ... on Report {
          name
          description
          published
        }
        ... on Grouping {
          name
          description
        }
        ... on CourseOfAction {
          name
          description
        }
        ... on Individual {
          name
          description
        }
        ... on Organization {
          name
          description
        }
        ... on Sector {
          name
          description
        }
        ... on System {
          name
          description
        }
        ... on Indicator {
          name
          description
          valid_from
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          description
          first_seen
          last_seen
        }
        ... on Position {
          name
          description
        }
        ... on City {
          name
          description
        }
        ... on AdministrativeArea {
          name
          description
        }
        ... on Country {
          name
          description
        }
        ... on Region {
          name
          description
        }
        ... on Malware {
          name
          description
          first_seen
          last_seen
        }
        ... on MalwareAnalysis {
          result_name
        }
        ... on ThreatActor {
          name
          description
          first_seen
          last_seen
        }
        ... on Tool {
          name
          description
        }
        ... on Task {
          name
        }
        ... on Narrative {
          name
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Event {
          name
        }
        ... on Incident {
          name
          description
          first_seen
          last_seen
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
          x_opencti_description
        }
        ... on StixFile {
          observableName: name
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

interface InvestigationAddStixCoreObjecstLineDummyProps {
  dataColumns: DataColumns
}

export const InvestigationAddStixCoreObjecstLineDummy = (
  { dataColumns }: InvestigationAddStixCoreObjecstLineDummyProps,
) => {
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
