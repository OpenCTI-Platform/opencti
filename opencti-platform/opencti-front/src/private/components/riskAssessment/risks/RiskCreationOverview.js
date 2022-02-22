import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import {
  compose,
  pipe,
  pluck,
  assoc,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer, QueryRenderer as QR } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import * as Yup from 'yup';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import { Information } from 'mdi-material-ui';
import Markdown from 'react-markdown';
import Tooltip from '@material-ui/core/Tooltip';
import AddIcon from '@material-ui/icons/Add';
import Cancel from '@material-ui/icons/Cancel';
import Button from '@material-ui/core/Button';
import MenuItem from '@material-ui/core/MenuItem';
import { IconButton } from '@material-ui/core';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import DatePickerField from '../../../../components/DatePickerField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import ConfidenceField from '../../common/form/ConfidenceField';
// import AssetTaglist from '../../common/form/AssetTaglist';
import AssetType from '../../common/form/AssetType';
// import Ports from '../../common/form/Ports';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

class RiskCreationOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      labelCreation: false,
    };
  }

  render() {
    const {
      t,
      classes,
      risk,
      context,
      values,
      onSubmit,
      setFieldValue,
      enableReferences,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3} style={{ marginBottom: '9px' }}>
            <Grid item={true} xs={6}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="id"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('POAM ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="poam_id"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3} style={{ marginBottom: '9px' }}>
            <Grid item={true} xs={6}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Created')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={DatePickerField}
                  variant='outlined'
                  size='small'
                  name="created"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Last Modified')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={DatePickerField}
                  variant='outlined'
                  size='small'
                  name="modified"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid item={true} xs={12} style={{ marginBottom: '15px' }}>
            <Typography
              variant="h3"
              color="textSecondary"
              gutterBottom={true}
              style={{ float: 'left' }}
            >
              {t('Description')}
            </Typography>
            <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
              <Tooltip
                title={t(
                  'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                )}
              >
                <Information fontSize="inherit" color="disabled" />
              </Tooltip>
            </div>
            <div className="clearfix" />
            <Field
              component={TextField}
              name="description"
              fullWidth={true}
              multiline={true}
              rows="4"
              variant='outlined'
            />
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid xs={6} item={true}>
              <Grid style={{ marginBottom: '58px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Weakness')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="weakness"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Risk Rating')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="risk_rating"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
              <Grid style={{ marginBottom: '15px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Impact')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="impact"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid style={{ marginBottom: '15px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Controls')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <AddIcon fontSize="small" style={{ margin: '-5px 0 0 0' }} />
                <div className="clearfix" />
                <Field
                  component={SelectField}
                  variant='outlined'
                  name="ports"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px', marginBottom: '3px' }}
                  containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                />
                <Field
                  component={SelectField}
                  variant='outlined'
                  name="ports"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Priority')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="priority"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
              <Grid style={{ marginBottom: '10px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Likelihood')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="likelihood"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid style={{ marginTop: '10px' }} item={true}>
            <Typography
              variant="h3"
              gutterBottom={true}
              color="textSecondary"
              style={{ float: 'left' }}
            >
              {t('Label')}
            </Typography>
            <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
              <Tooltip
                title={t(
                  'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                )}
              >
                <Information fontSize="inherit" color="disabled" />
              </Tooltip>
            </div>
            <div className="clearfix" />
            <ObjectLabelField
              variant='outlined'
              name="labels"
              style={{ marginTop: 10, width: '100%' }}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
            />
          </Grid>
        </Paper>
      </div>
    );
  }
}

RiskCreationOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  risk: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const RiskCreationOverview = createFragmentContainer(
  RiskCreationOverviewComponent,
  {
    risk: graphql`
      fragment RiskCreationOverview_risk on ThreatActor {
        id
        name
        threat_actor_types
        confidence
        description
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
              definition_type
            }
          }
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RiskCreationOverview);
