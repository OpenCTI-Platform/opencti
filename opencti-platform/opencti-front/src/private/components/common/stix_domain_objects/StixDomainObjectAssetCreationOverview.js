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
import DatePickerField from '../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import CreatedByField from '../form/CreatedByField';
import ObjectLabelField from '../form/ObjectLabelField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import ConfidenceField from '../form/ConfidenceField';
import AssetTaglist from '../form/AssetTaglist';
import AssetType from '../form/AssetType';
// import Ports from '../form/Ports';
import CommitMessage from '../form/CommitMessage';
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

class StixDomainObjectCreationOverviewComponent extends Component {
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
      stixDomainObject,
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
                  <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                    <Tooltip title={t('Installed Operating System')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
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
            </Grid>
            <Grid container={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                    >
                      {t('ID')}
                    </Typography>
                    <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                      <Tooltip title={t('Installed Operating System')} >
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
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
                  </div>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left', marginTop: 17 }}
                    >
                      {t('Asset ID')}
                    </Typography>
                    <div style={{ float: 'left', margin: '17px 0 0 5px' }}>
                      <Tooltip title={t('Installed Software')} >
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <Field
                      component={TextField}
                      variant='outlined'
                      size='small'
                      name="asset_id"
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    />
                  </div>
                </Grid>
                <Grid item={true} xs={6}>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                    >
                      {t('Asset Type')}
                    </Typography>
                    <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                      <Tooltip title={t('Asset Type')}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <AssetType
                      component={SelectField}
                      variant='outlined'
                      name="asset_type"
                      size='small'
                      disabled={true}
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                      helperText={t('Select Asset Type')}
                    />
                  </div>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left', marginTop: 20 }}
                    >
                      {t('Asset Tag')}
                    </Typography>
                    <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                      <Tooltip title={t('Asset Tag')}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <AssetTaglist
                      component={SelectField}
                      variant='outlined'
                      name="asset_tag"
                      size='small'
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                    >
                    </AssetTaglist>
                  </div>
                </Grid>
            </Grid>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={12}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 17 }}
                  >
                    {t('Description')}
                  </Typography>
                  <div style={{ float: 'left', margin: '17px 0 0 5px' }}>
                    <Tooltip title={t('Description')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                 <div className="clearfix" />
                  <Field
                  component={TextField}
                  name="Description"
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  variant='outlined'
                  />
              </Grid>
              <Grid item={true} xs={6}>
                <div style={{ marginTop: '6px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 15 }}
                  >
                    {t('Version')}
                  </Typography>
                  <div style={{ float: 'left', margin: '16px 0 0 5px' }}>
                    <Tooltip title={t('Version')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    size='small'
                    name="version"
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 16 }}
                  >
                    {t('Serial Number')}
                  </Typography>
                  <div style={{ float: 'left', margin: '18px 0 0 5px' }}>
                    <Tooltip title={t('Serial Number')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    size='small'
                    name="serial_number"
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 16 }}
                  >
                    {t('Responsible Parties')}
                  </Typography>
                  <div style={{ float: 'left', margin: '17px 0 0 5px' }}>
                    <Tooltip title={t('Responsible Parties')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="ports"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                  />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="ports"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Label')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Label')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <ObjectLabelField
                    variant='outlined'
                    name="labels"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.objectLabel}
                  />
                </div>
              </Grid>
              <Grid item={true} xs={6}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Vendor Name')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Vendor Name')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="vendor_name"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%' }}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Release Date')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Release Date')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={DatePickerField}
                    variant='outlined'
                    name="release_date"
                    size='small'
                    invalidDateMessage={t(
                      'The value must be a date (YYYY-MM-DD)',
                    )}
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%' }}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Operation State')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Operation State')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="operational_status"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%' }}
                  />
                </div>
              </Grid>
            </Grid>
        </Paper>
      </div>
    );
  }
}

StixDomainObjectCreationOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  stixDomainObject: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixDomainObjectCreationOverviewComponent);
