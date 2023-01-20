/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Chip from '@material-ui/core/Chip';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemConfidence from '../../../../components/ItemConfidence';
import ItemCreator from '../../../../components/ItemCreator';
import ItemBoolean from '../../../../components/ItemBoolean';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import ItemPatternType from '../../../../components/ItemPatternType';
import ItemMarkings from '../../../../components/ItemMarkings';
import StixCoreObjectOpinions from '../../analysis/opinions/StixCoreObjectOpinions';
import ItemIcon from '../../../../components/ItemIcon';
import CyioCoreObjectLabelsView from '../stix_core_objects/CyioCoreObjectLabelsView';

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

class CyioDomainObjectAssetOverview extends Component {
  render() {
    const {
      fd, t, fldt, classes, cyioDomainObject, withoutMarking, withPattern, refreshQuery,
    } = this.props;
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    // const otherCyioIds = cyioDomainObject?.x_opencti_cyio_ids || [];
    // const stixIds = R.filter(
    //   (n) => n !== cyioDomainObject?.standard_id,
    //   otherCyioIds,
    // );
    return (
      <div style={{ height: "100%" }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t("Basic information")}
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
                <div style={{ float: "left", margin: "2px 0 0 5px" }}>
                  <Tooltip title={t("Uniquely identifies this object")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {cyioDomainObject?.id && t(cyioDomainObject.id)}
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
                <Chip
                  avatar={
                    cyioDomainObject?.asset_type && (
                      <ItemIcon
                        variant="inline"
                        type={cyioDomainObject?.asset_type}
                        fontSize="5px"
                      />
                    )
                  }
                  classes={{ root: classes.chip }}
                  label={
                    cyioDomainObject?.asset_type &&
                    t(cyioDomainObject.asset_type)
                  }
                  color="primary"
                />
                {/* <ItemCreator creator={cyioDomainObject?.creator} /> */}
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
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip
                    title={t(
                      "Identifies the identifier defined by the standard"
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {cyioDomainObject?.asset_id && t(cyioDomainObject.asset_id)}
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
                {cyioDomainObject?.asset_tag && t(cyioDomainObject.asset_tag)}
              </div>
            </Grid>
            <Grid item={true} xs={12}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 20 }}
                >
                  {t("Description")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Description")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {cyioDomainObject?.description &&
                        t(cyioDomainObject.description)}
                    </div>
                  </div>
                </div>
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
                  {t("Version")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Version")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {cyioDomainObject?.version && t(cyioDomainObject.version)}
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
                  {t("Patch Level")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Patch Level")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {cyioDomainObject?.version && t(cyioDomainObject.patch_level)}
              </div>
            </Grid>
            <Grid item={true} xs={12}>
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
                {cyioDomainObject?.vendor_name &&
                  t(cyioDomainObject.vendor_name)}
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
                  {t("Serial Number")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Serial Number")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {cyioDomainObject?.serial_number &&
                  t(cyioDomainObject.serial_number)}
                {/* <ItemCreator creator={cyioDomainObject.creator} /> */}
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
                {cyioDomainObject?.release_date &&
                  fd(cyioDomainObject.release_date)}
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
                  {t("Responsible Parties")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Responsible Parties")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {cyioDomainObject?.responsible_parties &&
                  cyioDomainObject?.responsible_parties.map((data, key) => (
                    <Chip
                      key={key}
                      classes={{ root: classes.chip }}
                      label={t(data)}
                      color="primary"
                    />
                  ))}
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
                {cyioDomainObject?.operational_status &&
                  t(cyioDomainObject.operational_status)}
              </div>
            </Grid>
            <Grid item={true} xs={12}>
              <CyioCoreObjectLabelsView
                labels={cyioDomainObject.labels}
                marginTop={20}
                refreshQuery={refreshQuery}
                id={cyioDomainObject.id}
                typename={cyioDomainObject.__typename}
              />
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

CyioDomainObjectAssetOverview.propTypes = {
  cyioDomainObject: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
  fldt: PropTypes.func,
  fd: PropTypes.func,
  withoutMarking: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(CyioDomainObjectAssetOverview);
