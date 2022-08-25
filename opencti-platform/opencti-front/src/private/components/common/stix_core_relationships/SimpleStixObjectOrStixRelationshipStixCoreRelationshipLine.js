import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVertOutlined } from '@mui/icons-material';
import { AutoFix, VectorRadius } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipPopover from './StixCoreRelationshipPopover';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const styles = (theme) => ({
  item: {
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
});

class SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineComponent extends Component {
  render() {
    const {
      fsd,
      t,
      classes,
      dataColumns,
      node,
      paginationOptions,
      entityId,
      entityLink,
      connectionKey,
    } = this.props;
    const link = `${entityLink}/relations/${node.id}`;
    const isReversed = node.from?.id === entityId;
    const element = node.from?.id === entityId ? node.to : node.from;
    // Element can be null due to marking restrictions
    if (element === null) {
      return <div />;
    }
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={link}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <VectorRadius
            style={{ transform: isReversed ? 'rotate(-90deg)' : 'none' }}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.relationship_type.width }}
              >
                {t(`relationship_${node.relationship_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {element.relationship_type
                  ? t(`relationship_${element.entity_type}`)
                  : t(`entity_${element.entity_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {element.name
                  || element.attribute_abstract
                  || element.content
                  || element.observable_value
                  || t('Relationship')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fsd(node.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <ItemConfidence confidence={node.confidence} variant="inList" />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          {node.is_inferred ? (
            <Tooltip
              title={
                t('Inferred knowledge based on the rule ')
                + R.head(node.x_opencti_inferences).rule.name
              }
            >
              <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
            </Tooltip>
          ) : (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <StixCoreRelationshipPopover
                stixCoreRelationshipId={node.id}
                paginationOptions={paginationOptions}
                connectionKey={connectionKey}
              />
            </Security>
          )}
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  connectionKey: PropTypes.string,
};

const SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineFragment = createFragmentContainer(
  SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineComponent,
  {
    node: graphql`
        fragment SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine_node on StixCoreRelationship {
          id
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
          from {
            ... on StixDomainObject {
              id
              entity_type
              parent_types
              created_at
              updated_at
              objectLabel {
                edges {
                  node {
                    id
                    value
                    color
                  }
                }
              }
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
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
            ... on StixCyberObservable {
              id
              entity_type
              parent_types
              observable_value
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
                edges {
                  node {
                    id
                    definition
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
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
            }
          }
          to {
            ... on StixDomainObject {
              id
              entity_type
              parent_types
              created_at
              updated_at
              objectLabel {
                edges {
                  node {
                    id
                    value
                    color
                  }
                }
              }
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
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
            ... on StixCyberObservable {
              id
              entity_type
              parent_types
              observable_value
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
                edges {
                  node {
                    id
                    definition
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
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
            }
          }
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
      `,
  },
);

export const SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine = compose(
  inject18n,
  withStyles(styles),
)(SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineFragment);

class SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
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
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVertOutlined />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineDummy = compose(
  inject18n,
  withStyles(styles),
)(SimpleStixObjectOrStixRelationshipStixCoreRelationshipLineDummyComponent);
