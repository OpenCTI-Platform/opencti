import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { Grid, Switch, Tooltip } from '@material-ui/core';
import Chip from '@material-ui/core/Chip';
import Button from '@material-ui/core/Button';
import Link from '@material-ui/core/Link';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import Launch from '@material-ui/icons/Launch';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, Information } from 'mdi-material-ui';
import ListItemText from '@material-ui/core/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  link: {
    fontSize: '16px',
    font: 'DIN Next LT Pro',
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    padding: '14px 12px',
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

class RiskDetailsComponent extends Component {
  render() {
    const {
      t,
      classes,
      risk,
      fd,
      history,
    } = this.props;
    const relatedRisksEdges = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((value) => ({
        name: value.node.name,
        description: value.node.description,
        statement: value.node.statement,
        risk_status: value.node.risk_status,
        deadline: value.node.deadline,
        false_positive: value.node.false_positive,
        risk_adjusted: value.node.risk_adjusted,
        vendor_dependency: value.node.vendor_dependency,
      })),
    )(risk);
    const relatedObservationsEdges = R.pipe(
      R.pathOr([], ['related_observations', 'edges']),
      R.map((value) => ({
        impacted_component: value.node.impacted_component,
        impacted_asset: value.node.subjects,
      })),
    )(risk);
    console.log('RiskDetailsMain', relatedObservationsEdges);
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
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
                {t('Name')}
              </Typography>
              <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                <Tooltip
                  title={t(
                    'Name',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {risk.name && t(risk.name)} */}
              {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                <>
                  <div className="clearfix" />
                  {value.name}
                </>
              ))}
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Created')}
              </Typography>
              <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                <Tooltip
                  title={t(
                    'Created',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {t('Jun 11, 2021, 9:14:22 AM')}
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
              <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                <Tooltip
                  title={t(
                    'Last Modified',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {t('Jun 11, 2021, 9:14:22 AM')}
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
            <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Description')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
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
                      {/* {risk.description && t(risk.description)} */}
                      {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                        <>
                          <div className="clearfix" />
                          {value.description}
                        </>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Statement')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Statement',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className='scroll-bg'>
                  <div className={classes.scrollBg}>
                    <div className={classes.scrollDiv}>
                      <div className={classes.scrollObj}>
                        {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                          <>
                            <div className="clearfix" />
                            {value.statement}
                          </>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
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
                {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                  <>
                    <div className="clearfix" />
                    <Button
                      variant="outlined"
                      size="small"
                      style={{ cursor: 'default', marginBottom: '5px' }}
                      key={key}>
                      {value.risk_status}
                    </Button>
                  </>
                ))}
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
                {t('Lorem Ipsum Dolor Sit Amet')}
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
                {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                  <>
                    <div className="clearfix" />
                    <Button
                      variant="outlined"
                      size="small"
                      style={{ cursor: 'default', marginBottom: '5px' }}
                      key={key}>
                      {value.false_positive}
                    </Button>
                  </>
                ))}
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
                {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                  <>
                    <div className="clearfix" />
                    <Button
                      variant="outlined"
                      size="small"
                      style={{ cursor: 'default', marginBottom: '5px' }}
                      key={key}>
                      {value.risk_adjusted}
                    </Button>
                  </>
                ))}
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
                {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                  <>
                    <div className="clearfix" />
                    {fd(value.deadline)}
                  </>
                ))}
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
                {t('Lorem Ipsum Dono Ist')}
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
                {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                  <>
                    <div className="clearfix" />
                    <Button
                      variant="outlined"
                      size="small"
                      style={{ cursor: 'default', marginBottom: '5px' }}
                      key={key}>
                      {value.risk_adjusted}
                    </Button>
                  </>
                ))}
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
                {relatedRisksEdges?.length > 0 && relatedRisksEdges.map((value, key) => (
                  <>
                    <div className="clearfix" />
                    <Button
                      variant="outlined"
                      size="small"
                      style={{ cursor: 'default', marginBottom: '5px' }}
                      key={key}>
                      {value.vendor_dependency}
                    </Button>
                  </>
                ))}
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

RiskDetailsComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const RiskDetails = createFragmentContainer(
  RiskDetailsComponent,
  {
    risk: graphql`
      fragment RiskDetails_risk on POAMItem {
        id
        poam_id   #Item Id
        name      #Weakness
        description
        labels
        related_risks {
          edges {
            node {
              id
              name
              description
              statement
              risk_status         #Risk Status
              deadline
              priority
              accepted
              false_positive      #False-Positive
              risk_adjusted       #Operational Required
              vendor_dependency   #Vendor Dependency
              characterizations {
                id
                ... on GenericCharacterization {
                  origins {
                    id
                    origin_actors {
                      actor_type
                      actor {
                        ... on OscalPerson {
                          id
                          name    #Detection Source
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        related_observations {
          edges {
            node {
              id
              name              #Impacted Component
              subjects {
                subject {
                  ... on HardwareComponent {
                    id
                    name        #Impacted Asset
                  }
                }
              }
            }
          }
        }
        external_references {
          edges {
            node {
              id
              created
              modified
              external_id     #external id
              source_name     #Title
              description     #description
              url             #URL
              media_type      #media Type
            }
          }
        }
        notes {
          edges {
            node {
              id
              abstract
              content
              authors
              labels
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RiskDetails);
