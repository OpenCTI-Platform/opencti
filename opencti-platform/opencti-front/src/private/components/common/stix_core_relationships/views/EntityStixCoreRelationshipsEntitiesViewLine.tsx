import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import * as R from 'ramda';
import { KeyboardArrowRight } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import { DraftChip } from '@components/common/draft/DraftChip';
import ItemMarkings from '../../../../../components/ItemMarkings';
import StixCoreObjectLabels from '../../stix_core_objects/StixCoreObjectLabels';
import type { Theme } from '../../../../../components/Theme';
import { resolveLink } from '../../../../../utils/Entity';
import { useFormatter } from '../../../../../components/i18n';
import { DataColumns } from '../../../../../components/list_lines';
import { UseEntityToggle } from '../../../../../utils/hooks/useEntityToggle';
import ItemIcon from '../../../../../components/ItemIcon';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import {
  EntityStixCoreRelationshipsEntitiesViewLine_node$data,
  EntityStixCoreRelationshipsEntitiesViewLine_node$key,
} from './__generated__/EntityStixCoreRelationshipsEntitiesViewLine_node.graphql';
import ItemEntityType from '../../../../../components/ItemEntityType';

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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

const entityStixCoreRelationshipsEntitiesFragment = graphql`
  fragment EntityStixCoreRelationshipsEntitiesViewLine_node on StixCoreObject {
    id
    draftVersion {
      draft_id
      draft_operation
    }
    entity_type
    created_at
    ... on StixDomainObject {
      created
      modified
    }
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
      first_observed
      last_observed
    }
    ... on Opinion {
      opinion
    }
    ... on Report {
      name
      published
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
    ... on CaseIncident {
        name
    }
    ... on CaseRfi {
        name
    }
    ... on CaseRft {
        name
    }
    ... on StixCyberObservable {
      observable_value
    }
    createdBy {
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
`;

interface EntityStixCoreRelationshipsEntitiesLineProps {
  node: EntityStixCoreRelationshipsEntitiesViewLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: () => void;
  onToggleEntity: UseEntityToggle<{ id: string }>['onToggleEntity'];
  selectedElements: UseEntityToggle<{ id: string }>['selectedElements'];
  deSelectedElements: UseEntityToggle<{ id: string }>['deSelectedElements'];
  selectAll: UseEntityToggle<{ id: string }>['selectAll'];
  onToggleShiftEntity: (
    index: number,
    entity: EntityStixCoreRelationshipsEntitiesViewLine_node$data
  ) => void;
  index: number;
}

export const EntityStixCoreRelationshipsEntitiesViewLine: FunctionComponent<
EntityStixCoreRelationshipsEntitiesLineProps
> = ({
  node,
  dataColumns,
  onToggleEntity,
  selectAll,
  deSelectedElements,
  selectedElements,
  onLabelClick,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const { nsdt } = useFormatter();
  const stixCoreObject = useFragment(
    entityStixCoreRelationshipsEntitiesFragment,
    node,
  );
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
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, stixCoreObject)
          : onToggleEntity(stixCoreObject, event))
        }
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
        <ItemIcon type={stixCoreObject.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              <ItemEntityType entityType={stixCoreObject.entity_type} />
            </div>
            <div
              className={classes.bodyItem}
              style={{
                width: dataColumns.name
                  ? dataColumns.name.width
                  : dataColumns.observable_value.width,
              }}
            >
              {getMainRepresentative(stixCoreObject)}
              {stixCoreObject.draftVersion && (<DraftChip/>)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {R.pathOr('', ['createdBy', 'name'], stixCoreObject)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.creator.width }}
            >
              {(stixCoreObject.creators ?? []).map((c) => c?.name).join(', ')}
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
                variant="inList"
                markingDefinitions={stixCoreObject.objectMarking ?? []}
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
export const EntityStixCoreRelationshipsEntitiesLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
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
              style={{
                width: dataColumns.name
                  ? dataColumns.name.width
                  : dataColumns.observable_value.width,
              }}
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
