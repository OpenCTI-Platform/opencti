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
import LayersIcon from '@material-ui/icons/Layers';
import BuildIcon from '@material-ui/icons/Build';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert } from '@material-ui/icons';
import Skeleton from '@material-ui/lab/Skeleton';
import Button from '@material-ui/core/Button';
import * as R from 'ramda';
import inject18n from '../../../../../components/i18n';
import RemediationPopover from './RemediationPopover';
import { truncate } from '../../../../../utils/String';

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
    display: 'flex',
    overflow: 'hidden',
    alignItems: 'center',
    textOverflow: 'ellipsis',
    justifyContent: 'left',
    marginRight: '1rem',
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
      t,
      fldt,
      history,
      classes,
      riskId,
      node,
      paginationOptions,
    } = this.props;

    const SourceOfDetection = R.pipe(
      R.pathOr([], ['origins']),
      R.mergeAll,
      R.path(['origin_actors']),
      R.mergeAll,
    )(node);

    const orderedStartDate = R.sort((a, b) => Date.parse(a) - Date.parse(b));
    const orderedEndDate = R.sort((a, b) => Date.parse(b) - Date.parse(a));

    const startDate = R.pipe(
      R.map((n) => n.timing.start_date),
      orderedStartDate,
      R.head,
    )(R.pathOr([], ['tasks'], node));

    const endDate = R.pipe(
      R.map((n) => n.timing.end_date),
      orderedEndDate,
      R.head,
    )(R.pathOr([], ['tasks'], node));

    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/activities/risk_assessment/risks/${riskId}/remediation/${node.id}`}
      >
        <ListItemText
          primary={
            <div className={classes.ListItem}>
              <div className={classes.bodyItem}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  {SourceOfDetection.actor_type === 'assessment_platform'
                    && <LayersIcon className={classes.avatarIcon} />}
                  {SourceOfDetection.actor_type === 'tool'
                    && <BuildIcon className={classes.avatarIcon} />}
                  {SourceOfDetection.actor_type === 'party'
                    && <PersonIcon className={classes.avatarIcon} />}
                  <div style={{ marginLeft: '10px' }}>
                    <Typography variant="subtitle1">
                      {SourceOfDetection.actor_ref?.name
                        && truncate(t(SourceOfDetection.actor_ref?.name), 25)}
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
              {node?.tasks.length > 0
                ? <>
                    <div className={classes.bodyItem}>
                      <Typography align="left">
                        {node.created && fldt(startDate)}
                      </Typography>
                    </div>
                    <div className={classes.bodyItem}>
                      <Typography align="left">
                        {node.modified && fldt(endDate)}
                      </Typography>
                    </div>
                  </>
                : <>
                {/* <div style={{ display: 'grid', placeItems: 'center' }}>
                  -
                </div>
                <div style={{ display: 'grid', placeItems: 'center' }}>
                  -
                </div> */}
              </>}
            </div>
          }
        />
        <ListItemSecondaryAction>
          <RemediationPopover
            cyioCoreRelationshipId={node.id}
            paginationOptions={paginationOptions}
            history={history}
            riskId={riskId}
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
  location: PropTypes.object,
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
