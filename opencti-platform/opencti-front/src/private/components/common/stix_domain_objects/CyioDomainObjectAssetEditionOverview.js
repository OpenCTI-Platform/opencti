/* eslint-disable */
/* refactor */
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
import MenuItem from '@material-ui/core/MenuItem';
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
import SelectField from '../../../../components/SelectField';
import TextField from '../../../../components/TextField';
import OperationalStatusField from '../form/OperationalStatusField';
import MarkDownField from '../../../../components/MarkDownField';
import inject18n from '../../../../components/i18n';
import DatePickerField from '../../../../components/DatePickerField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import CyioCoreObjectLabelsView from '../stix_core_objects/CyioCoreObjectLabelsView';

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

class CyioDomainObjectAssetEditionOverviewComponent extends Component {
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
      cyioDomainObject,
      context,
      values,
      assetType,
      refreshQuery,
      onSubmit,
      setFieldValue,
      enableReferences,
    } = this.props;
    // const { editContext } = cyioDomainObject;
    // const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    return (
      <div style={{ height: "100%" }}>
        <Typography variant="h4" gutterBottom={true}>
          {t("Basic Information")}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("ID")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 2px 5px" }}>
                  <Tooltip title={t("Uniquely identifies this object")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={TextField}
                  variant="outlined"
                  size="small"
                  disabled={true}
                  name="id"
                  fullWidth={true}
                  containerstyle={{ width: "100%" }}
                  classes={{ root: classes.disabledFields }}
                  // onFocus={this.handleChangeFocus.bind(this)}
                  // onSubmit={this.handleSubmitField.bind(this)}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Asset Type")}
                </Typography>
                <div style={{ float: "left", margin: "2px 0 0 5px" }}>
                  <Tooltip title={t("Identifies the type of the Object")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <AssetType
                  component={SelectField}
                  variant="outlined"
                  name="asset_type"
                  assetType={assetType}
                  size="small"
                  fullWidth={true}
                  style={{ height: "38.09px" }}
                  containerstyle={{ width: "100%" }}
                  helperText={t("Select Asset Type")}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 20 }}
                >
                  {t("Asset ID")}
                </Typography>
                <div style={{ float: "left", margin: "20px 0 0 5px" }}>
                  <Tooltip
                    title={t(
                      "Identifies the identifier defined by the standard"
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={TextField}
                  variant="outlined"
                  size="small"
                  name="asset_id"
                  fullWidth={true}
                  containerstyle={{ width: "100%" }}
                  // onFocus={this.handleChangeFocus.bind(this)}
                  // onSubmit={this.handleSubmitField.bind(this)}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 20 }}
                >
                  {t("Asset Tag")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Asset Tag")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant="outlined"
                  size="small"
                  name="asset_tag"
                  fullWidth={true}
                  containerstyle={{ width: "100%" }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: "left", marginTop: 0 }}
              >
                {t("Description")}
              </Typography>
              <div style={{ float: "left", margin: "0 0 0 5px" }}>
                <Tooltip title={t("Description")}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <Field
                component={TextField}
                name="description"
                fullWidth={true}
                multiline={true}
                rows="3"
                variant="outlined"
              />
            </Grid>
            <Grid item={true} xs={6}>

                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Version")}
                </Typography>
                <div style={{ float: "left", margin: "0 0 0 5px" }}>
                  <Tooltip title={t("Version")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant="outlined"
                  size="small"
                  name="version"
                  fullWidth={true}
                  containerstyle={{ width: "100%" }}
                />

            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: "left" }}
              >
                {t("Patch Level")}
              </Typography>
              <div style={{ float: "left", margin: "0 0 0 5px" }}>
                <Tooltip title={t("Patch Level")}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <Field
                component={TextField}
                style={{ height: "38.09px" }}
                variant="outlined"
                name="patch_level"
                size="small"
                fullWidth={true}
                containerstyle={{ width: "100%", padding: "0 0 1px 0" }}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 20 }}
                >
                  {t("Vendor Name")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Vendor Name")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant="outlined"
                  name="vendor_name"
                  size="small"
                  fullWidth={true}
                  style={{ height: "38.09px" }}
                  containerstyle={{ width: "100%" }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 16 }}
                >
                  {t("Serial Number")}
                </Typography>
                <div style={{ float: "left", margin: "18px 0 0 5px" }}>
                  <Tooltip title={t("Serial Number")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant="outlined"
                  size="small"
                  name="serial_number"
                  fullWidth={true}
                  containerstyle={{ width: "100%" }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 20 }}
                >
                  {t("Release Date")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Release Date")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={DatePickerField}
                  variant="outlined"
                  name="release_date"
                  size="small"
                  invalidDateMessage={t(
                    "The value must be a date (YYYY-MM-DD)"
                  )}
                  fullWidth={true}
                  style={{ height: "38.09px" }}
                  containerstyle={{ width: "100%" }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 16 }}
                >
                  {t("Responsible Parties")}
                </Typography>
                <div style={{ float: "left", margin: "17px 0 0 5px" }}>
                  <Tooltip title={t("Responsible Parties")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={SelectField}
                  variant="outlined"
                  name="responsible_parties"
                  size="small"
                  fullWidth={true}
                  style={{ height: "38.09px" }}
                  containerstyle={{ width: "100%", padding: "0 0 1px 0" }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 20 }}
                >
                  {t("Operational Status")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Operation Status")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <OperationalStatusField
                  component={SelectField}
                  variant="outlined"
                  name="operational_status"
                  size="small"
                  fullWidth={true}
                  style={{ height: "38.09px" }}
                  containerstyle={{ width: "100%" }}
                  helperText={t("Select Operational Status")}
                />
              </div>
            </Grid>
            <Grid item={true} xs={12}>
              <CyioCoreObjectLabelsView
                labels={cyioDomainObject.labels}
                marginTop={20}
                refreshQuery={refreshQuery}
                id={cyioDomainObject?.id}
                typename={cyioDomainObject.__typename}
              />
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

CyioDomainObjectAssetEditionOverviewComponent.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  assetType: PropTypes.string,
  refreshQuery: PropTypes.func,
  cyioDomainObject: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CyioDomainObjectAssetEditionOverviewComponent);
