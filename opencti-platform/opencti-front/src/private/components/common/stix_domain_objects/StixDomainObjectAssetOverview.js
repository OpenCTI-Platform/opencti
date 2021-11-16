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

class StixDomainObjectAssetOverview extends Component {
  render() {
    const {
      t, fldt, classes, stixDomainObject, withoutMarking, withPattern,
    } = this.props;
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    const otherStixIds = stixDomainObject.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixDomainObject.standard_id,
      otherStixIds,
    );
    console.log('stixDomainObjectData', stixDomainObject);
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic information')}
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
                <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                  <Tooltip title={t('ID')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {stixDomainObject.id && t(stixDomainObject.id)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Asset ID')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Asset ID')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {stixDomainObject.asset_id && t(stixDomainObject.asset_id)}
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
                  <Tooltip
                    title={t('Asset Type')}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Chip
                  avatar={stixDomainObject.asset_type
                    && <ItemIcon type={stixDomainObject.asset_type} fontSize='5px' />}
                  classes={{ root: classes.chip }}
                  label={stixDomainObject.asset_type && t(stixDomainObject.asset_type)}
                  color="primary"
                />
                {/* <ItemCreator creator={stixDomainObject.creator} /> */}
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
                {stixDomainObject.asset_tag && t(stixDomainObject.asset_tag)}
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
                  {t('Description')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Description')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {stixDomainObject.description && t(stixDomainObject.description)}
                    </div>
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            {/* <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('ID')}
              </Typography>
              <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                <Tooltip
                  title={t(
                    'In OpenCTI, a predictable STIX ID is generated
                    based on one or multiple attributes of the entity.',
                  )}
                >
                  <Information fontSize="small" color="primary" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <pre style={{ margin: 0 }}>{stixDomainObject.standard_id}</pre>
            </Grid>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Asset Type')}
              </Typography>
              <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                <Tooltip title={t('Other known STIX IDs for this entity.')}>
                  <Information fontSize="small" color="primary" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <pre style={{ margin: 0 }}>
                {stixIds.length > 0
                  ? stixIds.map((stixId) => `${stixId}\n`)
                  : '-'}
              </pre>
            </Grid> */}
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Version')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t('Version')}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {stixDomainObject.version && t(stixDomainObject.version)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Serial Number')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Serial Number')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {stixDomainObject.serial_number && t(stixDomainObject.serial_number)}
                {/* <ItemCreator creator={stixDomainObject.creator} /> */}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Responsible Parties')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Responsible Parties')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {[1, 2].map((data, key) => (
                  <Chip key={key} classes={{ root: classes.chip }} label={t('Lorem Ipsum Lorem Ipsum')} color="primary" />
                ))}
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
                <StixCoreObjectLabels
                  labels={objectLabel}
                  marginTop={20}
                />
              </div>
              {/* {withPattern && (
                <div>
                  <Typography variant="h3"
                  color="textSecondary" gutterBottom={true}>
                    {t('Pattern type')}
                  </Typography>
                  <ItemPatternType label={stixDomainObject.pattern_type} />
                </div>
              )}
              {!withoutMarking && stixDomainObject.objectMarking && (
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ marginTop: withPattern ? 20 : 0 }}
                  >
                    {t('Marking')}
                  </Typography>
                  <ItemMarkings
                    markingDefinitions={R.pathOr(
                      [],
                      ['objectMarking', 'edges'],
                      stixDomainObject,
                    )}
                    limit={10}
                  />
                </div>
              )} */}
              {/* <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{
                  marginTop:
                    withPattern
                    || (!withoutMarking && stixDomainObject.objectMarking)
                      ? 20
                      : 0,
                }}
              >
                {t('Author')}
              </Typography>
              <ItemAuthor
                createdBy={R.propOr(null, 'createdBy', stixDomainObject)}
              />
              <StixCoreObjectOpinions
                stixCoreObjectId={stixDomainObject.id}
                variant="inEntity"
                height={160}
                marginTop={20}
              />
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creation date')}
              </Typography>
              {fldt(stixDomainObject.created)}
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Modification date')}
              </Typography>
              {fldt(stixDomainObject.modified)} */}
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
                {stixDomainObject.vendor_name && t(stixDomainObject.vendor_name)}
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
                {stixDomainObject.release_date && fldt(stixDomainObject.release_date)}
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
                {stixDomainObject.operational_status && t(stixDomainObject.operational_status)}
              </div>
              {/* <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Confidence level')}
              </Typography>
              <ItemConfidence confidence={stixDomainObject.confidence} />
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creation date (in this platform)')}
              </Typography>
              {fldt(stixDomainObject.created_at)}
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creator')}
              </Typography>
              <ItemCreator creator={stixDomainObject.creator} /> */}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

StixDomainObjectAssetOverview.propTypes = {
  stixDomainObject: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  withoutMarking: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectAssetOverview);
