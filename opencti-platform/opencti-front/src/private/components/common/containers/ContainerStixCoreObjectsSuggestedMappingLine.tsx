import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { CloseOutlined, MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import {
  ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$key,
} from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemMarkings from '../../../../components/ItemMarkings';
import { hexToRGB, itemColor } from '../../../../utils/Colors';
import { DataColumns } from '../../../../components/list_lines';
// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme: any) => ({
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
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
}));

interface ContainerStixCoreObjectsSuggestedMappingLineComponentProps {
  dataColumns: DataColumns;
  node: ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$key;
  contentMappingCount: Record<string, number>;
  handleRemoveSuggestedMappingLine: (matchedId: string) => void;
}

const ContainerStixCoreObjectsSuggestedMappingFragment = graphql`
    fragment ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity on MappedEntity {
      matchedString
      matchedEntity{
        id
        standard_id
        entity_type
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
        ... on Report {
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
        ... on Task {
          name
        }
        ... on StixCyberObservable {
          observable_value
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
      }
    }
  `;

export const ContainerStixCoreObjectsSuggestedMappingLine: FunctionComponent<
ContainerStixCoreObjectsSuggestedMappingLineComponentProps
> = ({ dataColumns, contentMappingCount, node, handleRemoveSuggestedMappingLine }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const mappedEntityData = useFragment(ContainerStixCoreObjectsSuggestedMappingFragment, node);
  const { matchedString, matchedEntity } = mappedEntityData;
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`${resolveLink(matchedEntity.entity_type)}/${matchedEntity.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={matchedEntity.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              <Chip
                classes={{ root: classes.chipInList }}
                style={{
                  backgroundColor: hexToRGB(itemColor(matchedEntity.entity_type), 0.08),
                  color: itemColor(matchedEntity.entity_type),
                  border: `1px solid ${itemColor(matchedEntity.entity_type)}`,
                }}
                label={t_i18n(`entity_${matchedEntity.entity_type}`)}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.matched_text.width }}
            >
              {matchedString}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {matchedEntity.createdBy?.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.value.width }}
            >
              {matchedEntity.x_mitre_id
                ? `[${matchedEntity.x_mitre_id}] ${matchedEntity.name}`
                : getMainRepresentative(matchedEntity)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectMarking.width }}
            >
              <ItemMarkings
                variant="inList"
                markingDefinitions={matchedEntity.objectMarking ?? []}
                limit={1}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.mapping.width }}
            >
              <Chip
                classes={{ root: classes.chipInList }}
                label={
                    contentMappingCount[matchedString]
                      ? contentMappingCount[matchedString]
                      : t_i18n('0')
                  }
              />
            </div>
          </>
        }
      />
      <ListItemSecondaryAction>
        <IconButton
          onClick={() => handleRemoveSuggestedMappingLine(matchedEntity.id)}
        >
          <CloseOutlined />
        </IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const ContainerStixCoreObjectsSuggestedMappingLineDummy = (props: ContainerStixCoreObjectsSuggestedMappingLineComponentProps) => {
  const classes = useStyles();
  const { dataColumns } = props;
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
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
              style={{ width: dataColumns.matched_text.width }}
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
              style={{ width: dataColumns.objectMarking.width }}
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
              style={{ width: dataColumns.mapping.width }}
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
        <IconButton disabled={true} aria-haspopup="true" size="large">
          <MoreVert/>
        </IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  );
};
