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
});

class RiskOverviewComponent extends Component {
  render() {
    const {
      t, fldt, classes, risk,
    } = this.props;
    // console.log('RiskOverview', risk);
    const riskEdges = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((value) => ({
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
    const relatedRisksEdges = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((value) => ({
        created: value.node.created,
        modified: value.node.modified,
        name: value.node.name,
        description: value.node.description,
        statement: value.node.statement,
        risk_status: value.node.risk_status,
        deadline: value.node.deadline,
        false_positive: value.node.false_positive,
        risk_adjusted: value.node.risk_adjusted,
        vendor_dependency: value.node.vendor_dependency,
        impacted_control_id: value.node.impacted_control_id,
      })),
      R.mergeAll,
    )(risk);
    const relatedObservationsEdges = R.pipe(
      R.pathOr([], ['related_observations', 'edges']),
      R.map((value) => ({
        impacted_component: value.node.impacted_component,
        impacted_asset: value.node.subjects,
      })),
    )(risk);
    const riskDetectionSource = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.mergeAll,
      R.pathOr([], ['node', 'characterizations']),
      R.mergeAll,
      R.path(['origins']),
      R.mergeAll,
      R.path(['origin_actors']),
      R.mergeAll,
    )(risk);
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        {/*  <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {risk.objectMarking.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
              risk.objectMarking.edges,
            )
          ) : (
            <ItemMarking label="TLP:WHITE" />
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fldt(risk.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(risk.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', risk)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={risk.description}
            limit={250}
          />
        </Paper> */}
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
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
              {risk.id && t(risk.id)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('POAM ID')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'POAM ID',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {risk.poam_id && t(risk.poam_id)}
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
              {risk.created && fd(risk.created)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Last Modified')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'Last Modified',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {t('Jun 11, 2021, 9:14:22 AM')} */}
              {risk.modified && fd(risk.modified)}
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
                    {risk.description && t(risk.description)}
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div style={{ marginBottom: '58px', marginTop: '10px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Weakness')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Weakness',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {risk.name && t(risk.name)}
              </div>
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
              <div style={{ marginTop: '10px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Controls')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Controls',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Chip key={risk.id} classes={{ root: classes.chip }} label={t('Lorem Ipsum Dono Ist Sei')} color="primary" />
                <br />
                <Chip key={risk.id} classes={{ root: classes.chip }} label={t('Lorem Ipsum Dono Ist Sei')} color="primary" />
                {/* <ItemCreator creator={risk.creator} /> */}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Priority')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
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
                marginTop={20}
                id={risk.id}
                typename={risk.__typename}
              />
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div style={{ marginTop: '15px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 5 }}
                >
                  {t('Risk Status')}
                </Typography>
                <div style={{ float: 'left', margin: '6px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Risk Status',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {/* {risk.risk_status && t(risk.risk_status)} */}
                <Button
                  variant="outlined"
                  size="small"
                  className={ classes.statusButton }
                >
                  {relatedRisksEdges.risk_status && t(relatedRisksEdges.risk_status)}
                </Button>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Detection Source')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Detection Source',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t(riskDetectionSource.actor.name)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('False Positive')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'False Positive',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Button
                  variant="outlined"
                  size="small"
                  className={ classes.statusButton }
                >
                  {relatedRisksEdges.false_positive && t(relatedRisksEdges.false_positive)}
                </Button>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 21 }}
                >
                  {t('Risk Adjusted')}
                </Typography>
                <div style={{ float: 'left', margin: '22px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Risk Adjusted',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Button
                  variant="outlined"
                  size="small"
                  className={ classes.statusButton }
                >
                  {relatedRisksEdges.risk_adjusted && t(relatedRisksEdges.risk_adjusted)}
                </Button>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div style={{ marginBottom: '12px', marginTop: '6px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 15 }}
                >
                  {t('Deadline')}
                </Typography>
                <div style={{ float: 'left', margin: '16px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Deadline',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {/* {risk.deadline && fd(risk.deadline)} */}
                {relatedRisksEdges.deadline && fd(relatedRisksEdges.deadline)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Impacted Control')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Impacted Control',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Operationally Required')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Operationally Required',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Button
                  variant="outlined"
                  size="small"
                  className={ classes.statusButton }
                >
                  {relatedRisksEdges.risk_adjusted && t(relatedRisksEdges.risk_adjusted)}
                </Button>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Vendor Dependency')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Vendor Dependency',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Button
                  variant="outlined"
                  size="small"
                  className={ classes.statusButton }
                >
                  {relatedRisksEdges.vendor_dependency && t(relatedRisksEdges.vendor_dependency)}
                </Button>
              </div>
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
        poam_id     # Item ID
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
            actor {
              ... on Component {
                id
                name
              }
              ... on OscalParty {
                id
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
                    actor {
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
