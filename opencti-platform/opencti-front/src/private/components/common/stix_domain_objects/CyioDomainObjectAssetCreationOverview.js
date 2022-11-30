/* eslint-disable */
/* refactor */
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
import CreatedByField from '../form/CreatedByField';
import ObjectLabelField from '../form/ObjectLabelField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import ConfidenceField from '../form/ConfidenceField';
import AssetType from '../form/AssetType';
import OperationalStatusField from '../form/OperationalStatusField';
import CommitMessage from '../form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import CyioCoreObjectLabelsView from '../../common/stix_core_objects/CyioCoreObjectLabelsView';

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
  disabledFields: {    
    "& .MuiOutlinedInput-input.Mui-disabled": {
      backgroundColor: 'rgba(241, 241, 242, 0.25)',
    },

    "& .MuiOutlinedInput-root.Mui-disabled .MuiOutlinedInput-notchedOutline": {
      borderColor: 'rgba(255, 255, 255, 0.23)',
      borderRadius: 'inherit',
    }
  },
});

class CyioDomainObjectAssetCreationOverviewComponent extends Component {
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
      context,
      values,
      onSubmit,
      setFieldValue,
      assetType,
      enableReferences,
    } = this.props;
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
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
                <Tooltip title={t('Name')} >
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
                  <Tooltip title={t('Uniquely identifies this object')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={TextField}
                  disabled={true}
                  variant='outlined'
                  size='small'
                  name="id"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                  classes={{ root: classes.disabledFields }}
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
                  <Tooltip title={t('Identifies the identifier defined by the standard')} >
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
                  <Tooltip title={t('Identifies the type of the Object')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <AssetType
                  component={SelectField}
                  variant='outlined'
                  name="asset_type"
                  assetType={assetType}
                  size='small'
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
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="asset_tag"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
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
                name="description"
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
                  disabled={true}
                  name="responsible_parties"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px', backgroundColor: 'rgba(241, 241, 242, 0.25)' }}
                  containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                />
                <Field
                  component={SelectField}
                  variant='outlined'
                  disabled={true}
                  name="responsible_parties"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px', backgroundColor: 'rgba(241, 241, 242, 0.25)' }}
                  containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                />
              </div>
              <div>
                <CyioCoreObjectLabelsView
                  labels={objectLabel}
                  marginTop={20}
                  disableAdd={true}
                  // id={cyioDomainObject?.id}
                />
                <div className="clearfix" />
                <ObjectLabelField
                  variant='outlined'
                  name="labels"
                  style={{ marginTop: 10, width: '100%', pointerEvents: 'none', backgroundColor: 'rgba(241, 241, 242, 0.25)' }}
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
                  {t('Operational Status')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Operation Status')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <OperationalStatusField
                  component={SelectField}
                  variant='outlined'
                  name="operational_status"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%' }}
                  helperText={t('Select Operational Status')}
                />
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

CyioDomainObjectAssetCreationOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  assetType: PropTypes.string,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CyioDomainObjectAssetCreationOverviewComponent);
