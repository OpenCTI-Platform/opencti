import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import * as R from 'ramda';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router-dom';
import { KeyboardArrowRight } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { resolveLink } from '../../../../utils/Entity';
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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

const EntitiesStixDomainObjectLineComponent = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const { fd } = useFormatter();
  const link = `${resolveLink(node.entity_type)}/${node.id}`;
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={link}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, node, event)
          : onToggleEntity(node, event))
        }
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(node.id in (deSelectedElements || {})))
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
              {R.pathOr('', ['createdBy', 'name'], node)}
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
                onClick={onLabelClick}
              />
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
              <ItemMarkings
                variant="inList"
                markingDefinitions={node.objectMarking ?? []}
                limit={1}
              />
            </div>
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItem>
  );
};

export const entitiesFragment = graphql`
  fragment EntitiesStixDomainObjectLine_node on StixDomainObject {
    id
    entity_type
    created_at
    ... on AttackPattern {
      name
      description
      aliases
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
    }
    ... on DataComponent {
      name
      aliases
      description
    }
    ... on DataSource {
      name
      aliases
      description
    }
    ... on Case {
      name
      description
    }
    ... on Task {
      name
      description
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
    ... on MalwareAnalysis {
      result_name
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
    ... on Task {
      name
    }
    createdBy {
      ... on Identity {
        name
      }
    }
    objectMarking {
      
          id
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
`;

export const EntitiesStixDomainObjectLine = createFragmentContainer(
  EntitiesStixDomainObjectLineComponent,
  {
    node: entitiesFragment,
  },
);

export const EntitiesStixDomainObjectLineDummy = ({ dataColumns }) => {
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
              style={{ width: dataColumns.created_at.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
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
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItem>
  );
};
