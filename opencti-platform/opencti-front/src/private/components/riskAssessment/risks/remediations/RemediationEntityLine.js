import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import Typography from '@material-ui/core/Typography';
import PersonIcon from '@material-ui/icons/Person';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert } from '@material-ui/icons';
import Skeleton from '@material-ui/lab/Skeleton';
import Button from '@material-ui/core/Button';
import Tooltip from '@material-ui/core/Tooltip';
import * as R from 'ramda';
import { AutoFix } from 'mdi-material-ui';
import inject18n from '../../../../../components/i18n';
import ItemConfidence from '../../../../../components/ItemConfidence';
import RemediationPopover from './RemediationPopover';
import { resolveLink } from '../../../../../utils/Entity';
import ItemIcon from '../../../../../components/ItemIcon';
import { defaultValue } from '../../../../../utils/Graph';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
  },
  ListItem: {
    display: 'grid',
    gridTemplateColumns: '20% 15% 15% 15% 1fr 1fr',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    float: 'left',
    height: '48px',
    display: 'flex',
    overflow: 'hidden',
    fontSize: '13px',
    alignItems: 'center',
    whiteSpace: 'nowrap',
    textOverflow: 'ellipsis',
    justifyContent: 'left',
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  avatarIcon: {
    width: '35px',
    height: '35px',
    color: 'white',
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
});

class RemediationEntityLineComponent extends Component {
  render() {
    const {
      fsd,
      t,
      fldt,
      history,
      classes,
      dataColumns,
      riskData,
      riskId,
      node,
      paginationOptions,
      displayRelation,
    } = this.props;
    const remediationTiming = R.pipe(
      R.pathOr([], ['tasks']),
      R.mergeAll,
    )(node);
    const remediationSource = R.pipe(
      R.pathOr([], ['origins']),
      R.mergeAll,
      R.path(['origin_actors']),
      R.mergeAll,
    )(node);
    let restricted = false;
    let targetEntity = null;
    if (node.from && node.from.id === riskId) {
      targetEntity = node.to;
    } else if (node.to && node.to.id === riskId) {
      targetEntity = node.from;
    } else {
      restricted = true;
    }
    if (targetEntity === null) {
      restricted = true;
    }
    // eslint-disable-next-line no-nested-ternary
    // const link = !restricted
    //   ? targetEntity.parent_types.includes('stix-core-relationship')
    //     ? `/dashboard/observations/observables/${riskId}/knowledge/relations/${node.id}`
    //     : `${resolveLink(targetEntity.entity_type)}/${targetEntity.id
    //     }/knowledge/relations/${node.id}`
    //   : null;
    const SourceOfDetection = R.pipe(
      R.pathOr([], ['origins']),
      R.mergeAll,
      R.path(['origin_actors']),
      R.mergeAll,
    )(node);
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/activities/risk assessment/risks/${riskId}/remediation/${node.id}`}
      // disabled={restricted}
      >
        <ListItemText
          primary={
            <div className={classes.ListItem}>
              <div className={classes.bodyItem}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <PersonIcon className={classes.avatarIcon} />
                  <div style={{ marginLeft: '10px' }}>
                    <Typography variant="subtitle1">
                      {SourceOfDetection.actor_ref?.name && t(SourceOfDetection.actor_ref?.name)}
                    </Typography>
                  </div>
                </div>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left">
                  {node.name && t(node.name)}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Button
                  variant='outlined'
                  size="small"
                  color='default'
                  className={classes.statusButton}
                >
                  {node.response_type && t(node.response_type)}
                </Button>
              </div>
              <div className={classes.bodyItem}>
                <Button
                  variant='outlined'
                  size="small"
                  color='default'
                  className={classes.statusButton}
                >
                  {node.lifecycle && t(node.lifecycle)}
                </Button>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left">
                  {node.created && fldt(node.created)}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left">
                  {node.modified && fldt(node.modified)}
                </Typography>
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <RemediationPopover
            cyioCoreRelationshipId={node.id}
            paginationOptions={paginationOptions}
            history={history}
            riskId={riskId}
          // disabled={restricted}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

RemediationEntityLineComponent.propTypes = {
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  history: PropTypes.object,
  t: PropTypes.func,
  riskData: PropTypes.object,
  riskId: PropTypes.string,
  fldt: PropTypes.func,
  fsd: PropTypes.func,
  displayRelation: PropTypes.bool,
};

const RemediationEntityLineFragment = createFragmentContainer(
  RemediationEntityLineComponent,
  {
    node: graphql`
      fragment RemediationEntityLine_node on RiskResponse {
        id
        name                # Title
        description         # Description
        created             # Created
        modified            # Last Modified
        response_type       # Response Type
        lifecycle           # Lifecycle
        origins{            # source of detection
          id
          origin_actors {
            actor_type
            actor_ref {
              ... on AssessmentPlatform {
                id
                name          # Source
              }
              ... on Component {
                id
                component_type
                name
              }
              ... on OscalParty {
              id
              party_type
              name            # Source
              }
            }
          }
        }
        tasks {             # only necessary if Start/End date is supported in UI
          __typename
          id
          entity_type
          task_type
          name
          description
          timing {
            ... on DateRangeTiming {
              start_date
              end_date
            }
          }
          task_dependencies {
            __typename
            id
            entity_type
            task_type
            name
          }
          associated_activities {
            __typename
            id
            entity_type
            activity_id {
              __typename
              id
              entity_type
              name
              description
              methods
            }
          }
          subjects {
            __typename
            id
            entity_type
            subject_type
            include_all
            include_subjects {
              id
              subject_type
              subject_context
              subject_ref {
                ... on Component {
                  id
                  entity_type
                  name
                }
                ... on InventoryItem {
                  id
                  entity_type
                  name
                }
                ... on OscalLocation {
                  id
                  entity_type
                  name
                }
                ... on OscalParty {
                  id
                  entity_type
                  name
                }
                ... on OscalUser {
                  id
                  entity_type
                  name
                }
              }
            }
            exclude_subjects {
              id
              subject_type
              subject_context
              subject_ref {
                ... on Component {
                  id
                  entity_type
                  name
                }
                ... on InventoryItem {
                  id
                  entity_type
                  name
                }
                ... on OscalLocation {
                  id
                  entity_type
                  name
                }
                ... on OscalParty {
                  id
                  entity_type
                  name
                }
                ... on OscalUser {
                  id
                  entity_type
                  name
                }
              }
            }
          }
          responsible_roles {
            __typename
            id
            entity_type
            role {
              __typename
              id
              entity_type
              role_identifier
              name
            }
            parties {
              __typename
              id
              entity_type
              party_type
              name
            }
          }
        }
      }
    `,
  },
);

export const RemediationEntityLine = R.compose(
  inject18n,
  withStyles(styles),
)(RemediationEntityLineFragment);

class RemediationEntityLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns, displayRelation } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Skeleton animation="wave" variant="circle" width={30} height={30} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              {displayRelation && (
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.relationship_type.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rect"
                    width="90%"
                    height="100%"
                  />
                </div>
              )}
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
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
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.start_time.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.stop_time.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
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
  }
}

RemediationEntityLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
  displayRelation: PropTypes.bool,
};

export const RemediationEntityLineDummy = R.compose(
  inject18n,
  withStyles(styles),
)(RemediationEntityLineDummyComponent);
