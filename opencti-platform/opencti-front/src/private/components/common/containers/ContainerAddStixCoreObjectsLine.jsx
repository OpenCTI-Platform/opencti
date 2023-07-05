import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { CheckCircleOutlined, CircleOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { defaultValue } from '../../../../utils/Graph';
import { hexToRGB, itemColor } from '../../../../utils/Colors';

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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: '0',
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
  const { t } = useFormatter();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      onClick={onToggleEntity.bind(this, node)}
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
              <Chip
                classes={{ root: classes.chipInList }}
                style={{
                  backgroundColor: hexToRGB(itemColor(node.entity_type), 0.08),
                  color: itemColor(node.entity_type),
                  border: `1px solid ${itemColor(node.entity_type)}`,
                }}
                label={t(`entity_${node.entity_type}`)}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.value.width }}
            >
              {defaultValue(node, true)}
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
                markingDefinitionsEdges={node.objectMarking.edges}
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
        standard_id
        parent_types
        entity_type
        created_at
        ... on AttackPattern {
          name
          description
          aliases
          x_mitre_id
        }
        ... on Campaign {
          name
          description
          aliases
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
          explanation
        }
        ... on Report {
          name
          description
        }
        ... on Grouping {
          name
          description
        }
        ... on CourseOfAction {
          name
          description
          x_opencti_aliases
          x_mitre_id
        }
        ... on Individual {
          name
          description
          x_opencti_aliases
        }
        ... on Organization {
          name
          description
          x_opencti_aliases
        }
        ... on Sector {
          name
          description
          x_opencti_aliases
        }
        ... on System {
          name
          description
          x_opencti_aliases
        }
        ... on Indicator {
          name
          description
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          aliases
          description
        }
        ... on Position {
          name
          description
          x_opencti_aliases
        }
        ... on City {
          name
          description
          x_opencti_aliases
        }
        ... on AdministrativeArea {
          name
          description
          x_opencti_aliases
        }
        ... on Country {
          name
          description
          x_opencti_aliases
        }
        ... on Region {
          name
          description
          x_opencti_aliases
        }
        ... on Malware {
          name
          aliases
          description
        }
        ... on ThreatActor {
          name
          aliases
          description
        }
        ... on Tool {
          name
          aliases
          description
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Incident {
          name
          aliases
          description
        }
        ... on Event {
          name
          description
          aliases
        }
        ... on Channel {
          name
          description
          aliases
        }
        ... on Narrative {
          name
          description
          aliases
        }
        ... on Language {
          name
          aliases
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
        }
        ... on IPv4Addr {
          countries {
            edges {
              node {
                name
                x_opencti_aliases
              }
            }
          }
        }
        ... on IPv6Addr {
          countries {
            edges {
              node {
                name
                x_opencti_aliases
              }
            }
          }
        }
        createdBy {
          ... on Identity {
            name
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
        creators {
          id
          name
        }
        reports {
          pageInfo {
            globalCount
          }
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
