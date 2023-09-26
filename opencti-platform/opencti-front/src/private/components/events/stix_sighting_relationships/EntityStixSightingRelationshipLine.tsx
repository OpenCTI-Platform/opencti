import React, { FunctionComponent } from 'react';
import * as R from 'ramda';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { HelpOutlined, MoreVertOutlined } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import { AutoFix } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import {
  EntityStixSightingRelationshipLine_node$key,
} from '@components/events/stix_sighting_relationships/__generated__/EntityStixSightingRelationshipLine_node.graphql';
import {
  EntityStixSightingRelationshipsLinesPaginationQuery$variables,
} from '@components/events/stix_sighting_relationships/__generated__/EntityStixSightingRelationshipsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixSightingRelationshipPopover from './StixSightingRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';
import { DataColumns } from '../../../../components/list_lines';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  positive: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  negative: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
    textTransform: 'uppercase',
    borderRadius: '0',
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

const EntityStixSightingRelationshipLineFragment = graphql`
    fragment EntityStixSightingRelationshipLine_node on StixSightingRelationship {
        id
        entity_type
        parent_types
        x_opencti_negative
        attribute_count
        confidence
        first_seen
        last_seen
        description
        is_inferred
        x_opencti_inferences {
            rule {
                id
                name
            }
        }
        from {
            ... on StixObject {
                id
                entity_type
                parent_types
                created_at
                updated_at
            }
            ... on AttackPattern {
                name
                description
                x_mitre_id
                killChainPhases {
                    edges {
                        node {
                            id
                            phase_name
                            x_opencti_order
                        }
                    }
                }
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
            ... on StixCyberObservable {
                observable_value
            }
        }
        to {
            ... on StixObject {
                id
                entity_type
                parent_types
                created_at
                updated_at
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
            ... on StixCyberObservable {
                observable_value
            }
        }
    }
`;

interface EntityStixSightingRelationshipLineProps {
  dataColumns: DataColumns;
  node: EntityStixSightingRelationshipLine_node$key;
  onLabelClick: () => void;
  isTo: boolean;
  paginationOptions?: EntityStixSightingRelationshipsLinesPaginationQuery$variables;
}

export const EntityStixSightingRelationshipLine: FunctionComponent<EntityStixSightingRelationshipLineProps> = (
  {
    dataColumns,
    node,
    paginationOptions,
    isTo,
  },
) => {
  const classes = useStyles();
  const { t, nsdt } = useFormatter();
  const data = useFragment<EntityStixSightingRelationshipLine_node$key>(
    EntityStixSightingRelationshipLineFragment,
    node,
  );
  const entity = isTo ? data.from : data.to;
  const restricted = entity === null;
  const entityLink = (entity?.entity_type) ? `${resolveLink(entity.entity_type)}/${entity.id}` : undefined;
  const link = `${entityLink}/knowledge/sightings/${data.id}`;
  return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={link}
        disabled={restricted}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={!restricted ? entity.entity_type : 'restricted'} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_negative.width }}
              >
                <Chip
                  classes={{
                    root: data.x_opencti_negative
                      ? classes.negative
                      : classes.positive,
                  }}
                  label={
                    data.x_opencti_negative
                      ? t('False positive')
                      : t('True positive')
                  }
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.attribute_count.width }}
              >
                {data.attribute_count}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {!restricted
                  ? entity.name || entity.observable_value
                  : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {!restricted
                  ? t(`entity_${entity.entity_type}`)
                  : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                {nsdt(data.first_seen)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                {nsdt(data.last_seen)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <ItemConfidence confidence={data.confidence} entityType={data.entity_type} variant="inList" />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          {data.is_inferred ? (
            <Tooltip
              title={
                `${t('Inferred knowledge based on the rule ')}
                ${R.head(data.x_opencti_inferences ?? [])?.rule.name ?? ''}`
              }
            >
              <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
            </Tooltip>
          ) : (
            <StixSightingRelationshipPopover
              stixSightingRelationshipId={data.id}
              paginationOptions={paginationOptions}
              disabled={restricted}
            />
          )}
        </ListItemSecondaryAction>
      </ListItem>
  );
};

export const EntityStixSightingRelationshipLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <HelpOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_negative.width }}
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
                style={{ width: dataColumns.attribute_count.width }}
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
                style={{ width: dataColumns.first_seen.width }}
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
                style={{ width: dataColumns.last_seen.width }}
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
                style={{ width: dataColumns.confidence.width }}
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
          <MoreVertOutlined />
        </ListItemSecondaryAction>
      </ListItem>
  );
};
