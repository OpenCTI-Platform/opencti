import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import React, { FunctionComponent } from 'react';
import { CircleOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import {
  StixNestedRefRelationshipCreationFromEntityLine_node$data,
  StixNestedRefRelationshipCreationFromEntityLine_node$key,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipCreationFromEntityLine_node.graphql';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import { APP_BASE_PATH } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemMarkings from '../../../../components/ItemMarkings';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
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
}));

const stixNestedRefRelationshipCreationFromEntityLineFragment = graphql`
  fragment StixNestedRefRelationshipCreationFromEntityLine_node on StixCoreObject {
    id
    standard_id
    parent_types
    entity_type
    created_at
    ... on BasicObject {
      id
      entity_type
      parent_types
    }
    ... on StixObject {
      created_at
      updated_at
    }
    ... on AttackPattern {
      name
      description
    }
    ... on Campaign {
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
    }
    ... on Infrastructure {
      name
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
      x_opencti_aliases
    }
    ... on Region {
      name
      description
    }
    ... on AdministrativeArea {
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
    ... on MalwareAnalysis {
      result_name 
    } 
    ... on StixCyberObservable {
      x_opencti_description
      observable_value
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
    ... on Case {
      name
    }
    ... on Report {
      name
    }
    ... on Grouping {
      name
    }
    ... on Note {
      attribute_abstract
      content
    }
    ... on Opinion {
      opinion
    }
    ... on ObservedData {
      name
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
    reports {
      pageInfo {
        globalCount
      }
    }
  }
`;

interface StixNestedRefRelationshipCreationFromEntityLineProps {
  node: StixNestedRefRelationshipCreationFromEntityLine_node$key,
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  onToggleEntity: (
    entity: StixNestedRefRelationshipCreationFromEntityLine_node$data,
    event?: React.SyntheticEvent
  ) => void;
  selectedElements: Record<string, StixNestedRefRelationshipCreationFromEntityLine_node$data>;
  deSelectedElements: Record<string, StixNestedRefRelationshipCreationFromEntityLine_node$data>;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: StixNestedRefRelationshipCreationFromEntityLine_node$data,
    event?: React.SyntheticEvent
  ) => void;
  index: number;
}

export const StixNestedRefRelationshipCreationFromEntityLine: FunctionComponent<StixNestedRefRelationshipCreationFromEntityLineProps> = ({
  node,
  dataColumns,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const data = useFragment(stixNestedRefRelationshipCreationFromEntityLineFragment, node);
  const flag = data.entity_type === 'Country'
    && (data.x_opencti_aliases ?? []).filter((n) => n?.length === 2)[0];
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      onClick={(event) => (event.shiftKey
        ? onToggleShiftEntity(index, data, event)
        : onToggleEntity(data, event))
      }
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, data, event)
          : onToggleEntity(data, event))
        }
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(data.id in (deSelectedElements || {})))
            || data.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        {flag ? (
          <img
            style={{ width: 20 }}
            src={`${APP_BASE_PATH}/static/flags/4x3/${flag.toLowerCase()}.svg`}
            alt={data.name}
          />
        ) : (
          <ItemIcon type={data.entity_type} />
        )}
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              <ItemEntityType entityType={data.entity_type} />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.value.width }}
            >
              {getMainRepresentative(data)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {data.createdBy?.name ?? ''}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={data.objectLabel}
                onClick={onLabelClick}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectMarking.width }}
            >
              <ItemMarkings
                variant="inList"
                markingDefinitions={data.objectMarking ?? []}
                limit={1}
              />
            </div>
          </div>
        }
      />
    </ListItem>
  );
};

export const StixNestedRefRelationshipCreationFromEntityLineDummy = ({
  dataColumns,
}: { dataColumns: DataColumns }) => {
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
                width="100%"
                height="100%"
              />
            </div>
          </div>
        }
      />
    </ListItem>
  );
};
