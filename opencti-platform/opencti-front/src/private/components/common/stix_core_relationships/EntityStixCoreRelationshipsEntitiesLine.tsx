import makeStyles from '@mui/styles/makeStyles';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import { HexagonOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import { pathOr } from 'ramda';
import { KeyboardArrowRight } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import React, { FunctionComponent } from 'react';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import ItemMarkings from '../../../../components/ItemMarkings';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import { UseEntityToggle } from '../../../../utils/hooks/useEntityToggle';
import {
  EntityStixCoreRelationshipsEntitiesLine_node$key,
} from './__generated__/EntityStixCoreRelationshipsEntitiesLine_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
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
    paddingRight: 5,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

const entityStixCoreRelationshipsEntitiesFragment = graphql`
  fragment EntityStixCoreRelationshipsEntitiesLine_node on StixCoreObject {
    id
    entity_type
    created_at
    ... on StixDomainObject {
      created
      modified
    }
    ... on AttackPattern {
      name
      description
    }
    ... on Campaign {
      name
      description
    }
    ... on Note {
      attribute_abstract
    }
    ... on ObservedData {
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
    }
    ... on Infrastructure {
      name
      description
    }
    ... on IntrusionSet {
      name
      description
    }
    ... on Position {
      name
      description
    }
    ... on City {
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
    }
    ... on ThreatActor {
      name
      description
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
    }
    ... on Event {
      name
      description
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
    ... on StixCyberObservable {
      observable_value
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectLabel {
      edges {
        node {
          value
          color
        }
      }
    }
    objectMarking {
      edges {
        node {
          definition
        }
      }
    }
  }
`;

interface EntityStixCoreRelationshipsEntitiesLineProps {
  node: EntityStixCoreRelationshipsEntitiesLine_node$key
  dataColumns: DataColumns
  onLabelClick: () => void
  onToggleEntity: UseEntityToggle<{ id: string }>['onToggleEntity']
  selectedElements: UseEntityToggle<{ id: string }>['selectedElements']
  deSelectedElements: UseEntityToggle<{ id: string }>['deSelectedElements']
  selectAll: UseEntityToggle<{ id: string }>['selectAll']
}

export const EntityStixCoreRelationshipsEntitiesLine: FunctionComponent<EntityStixCoreRelationshipsEntitiesLineProps> = ({
  node,
  dataColumns,
  onToggleEntity,
  selectAll,
  deSelectedElements,
  selectedElements,
  onLabelClick,
}) => {
  const classes = useStyles();
  const { t, nsdt } = useFormatter();

  const stixCoreObject = useFragment(entityStixCoreRelationshipsEntitiesFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => onToggleEntity(stixCoreObject, event)}
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(stixCoreObject.id in (deSelectedElements || {})))
            || stixCoreObject.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <HexagonOutline />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              {t(`entity_${stixCoreObject.entity_type}`)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {stixCoreObject.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={stixCoreObject.objectLabel}
                onClick={onLabelClick}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created_at.width }}
            >
              {nsdt(stixCoreObject.created_at)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectMarking.width }}
            >
              <ItemMarkings
                markingDefinitions={pathOr(
                  [],
                  ['objectMarking', 'edges'],
                  node,
                )}
                limit={1}
                variant="inList"
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
export const EntityStixCoreRelationshipsEntitiesLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <Checkbox edge="start" disabled={true} disableRipple={true} />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
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
