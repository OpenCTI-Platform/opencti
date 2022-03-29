/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Chip from '@material-ui/core/Chip';
import Button from '@material-ui/core/Button';
import { InformationOutline, Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import CyioCoreObjectLabelsView from '../../common/stix_core_objects/CyioCoreObjectLabelsView';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    textAlign: 'left',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
});

class RiskOverviewComponent extends Component {
  render() {
    const {
      t, fldt, classes, risk, refreshQuery,
    } = this.props;
    // console.log('RiskOverview', risk);
    const riskEdges = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((value) => ({
        id: value.node.id,
        created: value.node.created,
        modified: value.node.modified,
        name: value.node.name,
        description: value.node.description,
        deadline: value.node.deadline,
        priority: value.node.priority,
      })),
      R.mergeAll,
    )(risk);
    const relatedRiskData = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((relatedRisk) => ({
        characterization: relatedRisk.node.characterizations,
      })),
      R.mergeAll,
      R.path(['characterization']),
      R.mergeAll,
    )(risk);
    const riskFacets = R.pipe(
      R.pathOr([], ['facets']),
      R.mergeAll,
    )(relatedRiskData);
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('ID')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'ID',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {riskEdges.id && t(riskEdges.id)}
            </Grid>
          </Grid>
          <Grid style={{ marginTop: '10px' }} container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Created')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'Created',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {t('Jun 11, 2021, 9:14:22 AM')} */}
              {riskEdges.created && fldt(riskEdges.created)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Modified')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'Modified',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {t('Jun 11, 2021, 9:14:22 AM')} */}
              {riskEdges.modified && fldt(riskEdges.modified)}
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid style={{ marginTop: '10px' }} item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Description')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'Description',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {riskEdges.description && t(riskEdges.description)}
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: '10px' }}
                >
                  {t('Risk Rating')}
                </Typography>
                <div style={{ float: 'left', margin: '11px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Risk Rating',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {riskFacets.facet_name && t(riskFacets.facet_name)}
              </div>
              <div style={{ marginTop: '25px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Impact')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Version',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {riskFacets.risk_state && t(riskFacets.risk_state)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 10 }}
                >
                  {t('Priority')}
                </Typography>
                <div style={{ float: 'left', margin: '11px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Priority',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {/* {risk.priority && t(risk.priority)} */}
                {riskEdges.priority && t(riskEdges.priority)}
              </div>
              <div style={{ marginBottom: '20px', marginTop: '25px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Likelihood')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Likelihood',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {riskFacets.facet_value && t(riskFacets.facet_value)}
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <CyioCoreObjectLabelsView
                labels={risk.labels}
                marginTop={5}
                id={risk.id}
                refreshQuery={refreshQuery}
                typename={risk.__typename}
              />
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

RiskOverviewComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const RiskOverview = createFragmentContainer(
  RiskOverviewComponent,
  {
    risk: graphql`
      fragment RiskOverview_risk on POAMItem {
        __typename
        id
        created
        modified
        name        # Weakness
        description
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
        origins {
          id
          origin_actors {       # only use if UI support Detection Source
            actor_type
            actor_ref {
              ... on AssessmentPlatform {
                id
                name
              }
              ... on Component {
                id
                component_type
                name
              }
              ... on OscalParty {
                id
                party_type
                name
              }
            }
          }
        }
        links {
          __typename
          id
          created
          modified
          entity_type
          external_id     # external id
          source_name     # Title
          description     # description
          url             # URL
          media_type      # Media Type
        }
        remarks {
          __typename
          id
          abstract
          content
          authors
        }
        related_risks {
          edges {
            node{
              id
              created
              modified
              name
              description
              statement
              risk_status       # Risk Status
              deadline
              priority
              impacted_control_id
              accepted
              false_positive    # False-Positive
              risk_adjusted     # Operational Required
              vendor_dependency # Vendor Dependency
              characterizations {
                origins {
                  id
                  origin_actors {
                    actor_type
                    actor_ref {
                      ... on AssessmentPlatform {
                        id
                        name
                      }
                      ... on Component {
                        id
                        component_type
                        name          # Detection Source
                      }
                      ... on OscalParty {
                      id
                      party_type
                      name            # Detection Source
                      }
                    }
                  }
                }
                facets {
                  id
                  source_system
                  facet_name
                  facet_value
                  risk_state
                  entity_type
                }
              }
              remediations {
                response_type
                lifecycle
              }
            }
          }
        }
      }
    `,
  },
);

export default R.compose(inject18n, withStyles(styles))(RiskOverview);
