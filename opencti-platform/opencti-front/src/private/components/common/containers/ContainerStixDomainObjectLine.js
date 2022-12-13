import React from 'react';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import Checkbox from '@mui/material/Checkbox';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { AutoFix } from 'mdi-material-ui';
import { useFormatter } from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import ItemIcon from '../../../../components/ItemIcon';
import ContainerStixCoreObjectPopover from './ContainerStixCoreObjectPopover';
import { resolveLink } from '../../../../utils/Entity';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import { defaultValue } from '../../../../utils/Graph';

const useStyles = makeStyles((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemDisabled: {
    paddingLeft: 10,
    height: 50,
    color: theme.palette.grey[700],
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
    paddingRight: 5,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
}));

const ContainerStixDomainObjectLineComponent = (props) => {
  const {
    node,
    types,
    dataColumns,
    containerId,
    paginationOptions,
    onToggleEntity,
    selectedElements,
    deSelectedElements,
    selectAll,
  } = props;
  const classes = useStyles();
  const { t, fd } = useFormatter();
  const refTypes = types ?? ['manual'];
  const isThroughInference = refTypes.includes('inferred');
  const isOnlyThroughInference = isThroughInference && !refTypes.includes('manual');

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`${resolveLink(node.entity_type)}/${node.id}`}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => !isOnlyThroughInference && onToggleEntity(node, event)
        }
      >
        <Checkbox
          edge="start"
          disabled={isOnlyThroughInference}
          checked={
            (selectAll
              && !isOnlyThroughInference
              && !(node.id in (deSelectedElements || {})))
            || node.id in (selectedElements || {})
          }
          disableRipple={true}
        />
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
              {t(`entity_${node.entity_type}`)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {node.x_mitre_id
                ? `[${node.x_mitre_id}] ${node.name}`
                : defaultValue(node)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={node.objectLabel}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {R.pathOr('', ['createdBy', 'name'], node)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created_at.width }}
            >
              {fd(node.created_at)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectMarking.width }}
            >
              {R.take(1, R.pathOr([], ['objectMarking', 'edges'], node)).map(
                (markingDefinition) => (
                  <ItemMarking
                    key={markingDefinition.node.id}
                    variant="inList"
                    label={markingDefinition.node.definition}
                    color={markingDefinition.node.x_opencti_color}
                  />
                ),
              )}
            </div>
          </div>
        }
      />
      <ListItemSecondaryAction>
        {isOnlyThroughInference ? (
          <Tooltip title={t('Inferred knowledge')}>
            <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
          </Tooltip>
        ) : (
          <ContainerStixCoreObjectPopover
            containerId={containerId}
            toId={node.id}
            relationshipType="object"
            paginationKey="Pagination_objects"
            paginationOptions={paginationOptions}
          />
        )}
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const ContainerStixDomainObjectLine = createFragmentContainer(
  ContainerStixDomainObjectLineComponent,
  {
    node: graphql`
      fragment ContainerStixDomainObjectLine_node on StixDomainObject {
        id
        entity_type
        parent_types
        created_at
        ... on AttackPattern {
          name
          x_mitre_id
        }
        ... on Campaign {
          name
        }
        ... on CourseOfAction {
          name
        }
        ... on ObservedData {
          name
        }
        ... on Grouping {
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
        ... on Country {
          name
        }
        ... on Region {
          name
        }
        ... on Malware {
          name
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
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
              x_opencti_color
            }
          }
        }
      }
    `,
  },
);

export const ContainerStixDomainObjectLineDummy = (props) => {
  const classes = useStyles();
  const { dataColumns } = props;
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <Checkbox edge="start" disabled={true} disableRipple={true} />
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
              style={{ width: dataColumns.created_at.width }}
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
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <MoreVert />
      </ListItemSecondaryAction>
    </ListItem>
  );
};
