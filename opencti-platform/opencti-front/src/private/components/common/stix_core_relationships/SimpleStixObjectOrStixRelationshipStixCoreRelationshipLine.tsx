import React from 'react';
import { Link } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVertOutlined } from '@mui/icons-material';
import { AutoFix } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import { ListItemButton } from '@mui/material';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data$data } from './__generated__/SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data.graphql';
import { SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine_node$key } from './__generated__/SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine_node.graphql';
import { DraftChip, getDraftModeColor } from '../draft/DraftChip';
import { useFormatter } from '../../../../components/i18n';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipPopover from './StixCoreRelationshipPopover';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import {
  SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery$variables,
} from './__generated__/SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
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

const SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineFragment = graphql`
  fragment SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine_node on StixCoreRelationship {
    id
    draftVersion {
      draft_id
      draft_operation
    }
    entity_type
    parent_types
    relationship_type
    confidence
    start_time
    stop_time
    description
    is_inferred
    created_at
    x_opencti_inferences {
      rule {
        id
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
    from {
      ... on StixDomainObject {
        representative {
          main
        }
        id
        draftVersion {
          draft_id
          draft_operation
        }
        entity_type
        parent_types
        created_at
        updated_at
        objectLabel {
          id
          value
          color
        }
      }
      ... on AttackPattern {
        name
        description
        x_mitre_id
        killChainPhases {
          id
          phase_name
          x_opencti_order
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
      ... on MalwareAnalysis {
        result_name
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
      ... on StixCyberObservable {
        id
        entity_type
        parent_types
        observable_value
        representative {
          main
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
      }
      ... on Indicator {
        id
        name
        pattern_type
        pattern_version
        description
        valid_from
        valid_until
        x_opencti_score
        x_opencti_main_observable_type
        created
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
      }
      ... on BasicRelationship {
        id
        entity_type
        parent_types
      }
      ... on StixCoreRelationship {
        relationship_type
        representative {
          main
        }
        from {
          ... on BasicObject {
            id
            entity_type
          }
          ... on BasicRelationship {
            id
          }
          ... on StixCyberObservable {
            representative {
              main
            }
          }
          ... on StixDomainObject {
            representative {
              main
            }
          }
        }
        to {
          ... on BasicObject {
            id
            entity_type
          }
          ... on BasicRelationship {
            id
          }
          ... on StixCyberObservable {
            representative {
              main
            }
          }
          ... on StixDomainObject {
            representative {
              main
            }
          }
        }
      }
    }
    fromId
    fromType
    to {
      ... on StixDomainObject {
        id
        representative {
          main
        }
        draftVersion {
          draft_id
          draft_operation
        }
        entity_type
        parent_types
        created_at
        updated_at
        objectLabel {
          id
          value
          color
        }
      }
      ... on AttackPattern {
        name
        description
        x_mitre_id
        killChainPhases {
          id
          phase_name
          x_opencti_order
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
      ... on MalwareAnalysis {
        result_name
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
      ... on StixCyberObservable {
        id
        entity_type
        parent_types
        observable_value
        representative {
          main
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
      }
      ... on Indicator {
        id
        name
        pattern_type
        pattern_version
        description
        valid_from
        valid_until
        x_opencti_score
        x_opencti_main_observable_type
        created
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
      }
      ... on BasicRelationship {
        id
        entity_type
        parent_types
      }
      ... on StixCoreRelationship {
        relationship_type
        representative {
          main
        }
      }
    }
    toId
    toType
    killChainPhases {
      id
      phase_name
      x_opencti_order
    }
  }
`;

interface SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineProps {
  dataColumns: DataColumns,
  node: NonNullable<SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data$data['stixCoreRelationships']>['edges'][0]['node'],
  paginationOptions: SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery$variables,
  entityId: string,
  entityLink: string,
  connectionKey: string,
}

const SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine = ({
  dataColumns,
  node,
  paginationOptions,
  entityId,
  entityLink,
  connectionKey,
}: SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineProps) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t_i18n, fsd } = useFormatter();

  const data = useFragment<SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine_node$key>(SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineFragment, node);

  const link = `${entityLink}/relations/${data.id}`;
  const isReversed = data.fromId === entityId;
  const row = isReversed ? data.to : data.from;
  const element = row || {
    id: isReversed ? data.toId : data.fromId,
    entity_type: 'Restricted',
    restricted: true,
    representative: { main: t_i18n('Restricted') },
    draftVersion: null,
  };
  const draftColor = getDraftModeColor(theme);
  return (
    <ListItem
      divider={true}
      disablePadding
      secondaryAction={data.is_inferred ? (
        <Tooltip
          title={
              t_i18n('Inferred knowledge based on the rule ')
              + (data.x_opencti_inferences?.[0]?.rule.name ?? '')
            }
        >
          <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
        </Tooltip>
      ) : (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipPopover
            stixCoreRelationshipId={data.id}
            paginationOptions={paginationOptions}
            connectionKey={connectionKey}
          />
        </Security>
      )}
    >
      <ListItemButton
        classes={{ root: classes.item }}
        component={Link}
        to={link}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={data.entity_type} isReversed={isReversed} color={data.draftVersion ? draftColor : null} />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.relationship_type.width }}
              >
                <ItemEntityType
                  entityType={data.relationship_type}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <ItemEntityType
                  entityType={element.entity_type ?? ''}
                  size='large'
                  showIcon
                  isRestricted={!row}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {element.representative?.main}
                {element.draftVersion && (<DraftChip/>)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fsd(data.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <ItemConfidence
                  confidence={data.confidence}
                  entityType={data.entity_type}
                  variant="inList"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.markings.width }}
              >
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={data.objectMarking ?? []}
                  limit={1}
                />
              </div>
            </>
          }
        />
      </ListItemButton>
    </ListItem>
  );
};

export default SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine;

export const SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={
        <Box sx={{ root: classes.itemIconDisabled }}>
          <MoreVertOutlined/>
        </Box>
        }
    >
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
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
              style={{ width: dataColumns.relationship_type.width }}
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
              style={{ width: dataColumns.name.width }}
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
    </ListItem>
  );
};
