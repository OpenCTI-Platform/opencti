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
import FormControl from '@material-ui/core/FormControl';
import AddIcon from '@material-ui/icons/Add';
import Cancel from '@material-ui/icons/Cancel';
import Button from '@material-ui/core/Button';
import MenuItem from '@material-ui/core/MenuItem';
import Select from '@material-ui/core/Select';
import { IconButton } from '@material-ui/core';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import DatePickerField from '../../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import { commitMutation } from '../../../../../relay/environment';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import CreatedByField from '../../../common/form/CreatedByField';
import ObjectLabelField from '../../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../../components/MarkDownField';
import SelectField from '../../../../../components/SelectField';
import ConfidenceField from '../../../common/form/ConfidenceField';
// import AssetTaglist from '../../../common/form/AssetTaglist';
import AssetType from '../../../common/form/AssetType';
// import Ports from '../../../common/form/Ports';
import CommitMessage from '../../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../../utils/String';

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

class RemediationCreationOverviewComponent extends Component {
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
      remediation,
      context,
      values,
      onSubmit,
      setFieldValue,
      enableReferences,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid xs={6} item={true}>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Name')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Name')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="name"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                // onFocus={this.handleChangeFocus.bind(this)}
                // onSubmit={this.handleSubmitField.bind(this)}
                />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Created')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Created')}>
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
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD)',
                  )}
                  style={{ height: '38.09px' }}
                />
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('ID')}>
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
                // helperText={
                //   <SubscriptionFocus fieldName="name" />
                // }
                />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Last Modified')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Last Modified')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={DatePickerField}
                  variant='outlined'
                  size='small'
                  name="modified"
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD)',
                  )}
                  style={{ height: '38.09px' }}
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid style={{ marginTop: '10px' }} item={true}>
            <Typography
              variant="h3"
              color="textSecondary"
              gutterBottom={true}
              style={{ float: 'left' }}
            >
              {t('Description')}
            </Typography>
            <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
              <Tooltip title={t('Label')}>
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
        </Paper>
      </div>
    );
  }
}

RemediationCreationOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  remediation: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const RemediationCreationOverview = createFragmentContainer(
  RemediationCreationOverviewComponent,
  {
    remediation: graphql`
      fragment RemediationCreationGeneral_remediation on RiskResponse {
        id
        name              # Title
        description       # Description
        created           # Created
        modified          # Last Modified
        lifecycle         # Lifecycle
        response_type     # Response Type
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
                name
              }
              ... on OscalParty {
                id
                party_type
                name      # source
              }
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
)(RemediationCreationOverview);
