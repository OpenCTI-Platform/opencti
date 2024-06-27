import React, { FunctionComponent, SyntheticEvent } from 'react';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemStatus from '../../../../components/ItemStatus';
import ItemMarkings from '../../../../components/ItemMarkings';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import { StixCoreObjectOrStixCoreRelationshipContainerLine_node$data } from './__generated__/StixCoreObjectOrStixCoreRelationshipContainerLine_node.graphql';
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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

interface StixCoreObjectOrStixCoreRelationshipContainerLineComponentProps {
  node: StixCoreObjectOrStixCoreRelationshipContainerLine_node$data;
  dataColumns: DataColumns;
  onLabelClick: (
    key: string,
    id: string,
    value: string,
    event: SyntheticEvent
  ) => void;
  redirectionMode: string;
}

export const StixCoreObjectOrStixCoreRelationshipContainerLineComponent: FunctionComponent<
StixCoreObjectOrStixCoreRelationshipContainerLineComponentProps
> = ({ node, dataColumns, onLabelClick, redirectionMode }) => {
  const classes = useStyles();
  const { fd } = useFormatter();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={
        !redirectionMode
        || redirectionMode === 'overview'
        || node.entity_type !== 'Report'
          ? `${resolveLink(node.entity_type)}/${node.id}`
          : `${resolveLink(node.entity_type)}/${node.id}/${redirectionMode}`
      }
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={node.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              <ItemEntityType entityType={node.entity_type} />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {getMainRepresentative(node)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {node.createdBy?.name ?? ''}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.creator.width }}
            >
              {(node.creators ?? []).map((c) => c?.name).join(', ')}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={node.objectLabel}
                onClick={onLabelClick.bind(this)}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created.width }}
            >
              {fd(node.first_observed || node.published || node.created)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.x_opencti_workflow_id.width }}
            >
              <ItemStatus
                status={node.status}
                variant="inList"
                disabled={!node.workflowEnabled}
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
          </>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

const StixCoreObjectOrStixCoreRelationshipContainerLineFragment = createFragmentContainer(
  StixCoreObjectOrStixCoreRelationshipContainerLineComponent,
  {
    node: graphql`
        fragment StixCoreObjectOrStixCoreRelationshipContainerLine_node on Container {
          id
          workflowEnabled
          entity_type
          status {
            id
            order
            template {
              name
              color
            }
          }
          creators {
            id
            name
          }
          ... on Note {
            attribute_abstract
            content
            created
          }
          ... on Opinion {
            opinion
            created
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Report {
            name
            published
          }
          ... on Grouping {
            name
            created
          }
          ... on Case {
            name
            created
          }
          ... on Task {
            name
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
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
          ... on ObservedData {
            name
            objects(first: 1) {
              edges {
                node {
                  ... on StixCoreObject {
                    id
                    entity_type
                    parent_types
                    created_at
                    createdBy {
                      ... on Identity {
                        id
                        name
                        entity_type
                      }
                    }
                    objectMarking {
                      id
                      definition_type
                      definition
                      x_opencti_order
                      x_opencti_color
                    }
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
                  ... on Note {
                    attribute_abstract
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
                  ... on Vulnerability {
                    name
                    description
                  }
                  ... on Incident {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Event {
                    name
                    description
                    start_time
                    stop_time
                  }
                  ... on Channel {
                    name
                    description
                  }
                  ... on Narrative {
                    name
                    description
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
                    x_opencti_description
                  }
                }
              }
            }
          }
        }
      `,
  },
);

export const StixCoreObjectOrStixCoreRelationshipContainerLine = StixCoreObjectOrStixCoreRelationshipContainerLineFragment;

interface StixCoreObjectOrStixCoreRelationshipContainerLineDummyProps {
  dataColumns: DataColumns;
}

export const StixCoreObjectOrStixCoreRelationshipContainerLineDummy: FunctionComponent<
StixCoreObjectOrStixCoreRelationshipContainerLineDummyProps
> = ({ dataColumns }) => {
  const classes = useStyles();

  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
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
              style={{ width: dataColumns.name.width }}
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
              style={{ width: dataColumns.creator.width }}
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
              style={{ width: dataColumns.created.width }}
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
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
