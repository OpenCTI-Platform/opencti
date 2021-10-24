import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import * as R from 'ramda';
import {
  assoc,
  difference,
  head,
  join,
  map,
  pathOr,
  pick,
  pipe,
  split,
  compose,
} from 'ramda';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import {
  commitMutation,
  requestSubscription,
} from '../../../../relay/environment';
import AssetType from '../form/AssetType';
import AssetTaglist from '../form/AssetTaglist';
import SelectField from '../../../../components/SelectField';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import inject18n from '../../../../components/i18n';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';

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

class StixDomainObjectAssetEditionOverviewComponent extends Component {
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
    const { editContext } = stixDomainObject;
    console.log('fetched data ', stixDomainObject);
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
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
                // onFocus={this.handleChangeFocus.bind(this)}
                // onSubmit={this.handleSubmitField.bind(this)}
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
                  // onFocus={this.handleChangeFocus.bind(this)}
                  // onSubmit={this.handleSubmitField.bind(this)}
                />
              </div>
              {/* <div>
                      <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                        <Tooltip title={t('Description')} >
                          <Information fontSize="small" color="primary" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <textarea className="scrollbar-customize" rows="3" cols="24" />
                    </div> */}
              <div>
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
                {/* <div className="clearfix" />
                      <textarea className="scrollbar-customize" rows="3" cols="24" /> */}
                <div className="clearfix" />
                <div className='scroll-bg'>
                  <div className='scroll-div'>
                    <div className='scroll-object'>
                      <Field
                        component={TextField}
                        multiline={true}
                        variant='outlined'
                        size='small'
                        name="description"
                        fullWidth={true}
                        containerstyle={{ width: '100%', height: '100%' }}
                      />
                    </div>
                  </div>
                </div>
              </div>
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
                  <Tooltip
                    title={t(
                      'Version',
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
                  <Tooltip
                    title={t(
                      'Serial Number',
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
                  <Tooltip
                    title={t(
                      'Responsible Parties',
                    )}
                  >
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
                  containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                // helperText={
                //   <SubscriptionFocus
                //   context={context}
                //   fieldName="ports"
                //   />
                // }
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
                  <Tooltip
                    title={t(
                      'Label',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {/* <StixCoreObjectLabelsView
                        labels={device.objectLabel}
                        marginTop={20}
                      /> */}
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
                >
                </AssetType>
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
                  component={TextField}
                  variant='outlined'
                  name="release_date"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%' }}
                // helperText={
                //   <SubscriptionFocus
                //   context={context}
                //   fieldName="ReleaseDate"
                //   />
                // }
                />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Operational State')}
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

StixDomainObjectAssetEditionOverviewComponent.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  stixDomainObject: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixDomainObjectAssetEditionOverviewComponent);
