import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr, map } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Chip from '@material-ui/core/Chip';
import { InformationOutline, Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../../components/i18n';
import ItemAuthor from '../../../../../components/ItemAuthor';
import ItemMarking from '../../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../../components/ExpandableMarkdown';

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

class RemediationGeneralOverviewComponent extends Component {
  render() {
    const {
      t, fldt, classes, risk,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Remediation Item')}
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
              <div style={{ marginBottom: '46px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 15 }}
                >
                  {t('Title')}
                </Typography>
                <div className="clearfix" />
                {t('Lorem Ipsum Dolor Sit Amet')}
              </div>
              <div style={{ marginBottom: '33px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 16 }}
                >
                  {t('ID')}
                </Typography>
                <div className="clearfix" />
                {t('Lorem Ipsum Dolor Sit Amet')}
              </div>
              <div style={{ marginBottom: '26px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 25 }}
                >
                  {t('Created')}
                </Typography>
                <div className="clearfix" />
                {t('Lorem Ipsum Dolor Sit Amet')}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 5 }}
                >
                  {t('Response Type')}
                </Typography>
                <div className="clearfix" />
                <Button variant="outlined" color="success" >Deviation Approved</Button>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div style={{ marginBottom: '10px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 15 }}
                >
                  {t('Source')}
                </Typography>
                <div className="clearfix" />
                <div style={{ display: 'flex' }}>
                  <Badge
                    overlap="circular"
                    anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
                    badgeContent={
                      <Avatar style={{ width: 15, height: 15, backgroundColor: 'green' }} alt="Remy Sharp" />
                    }
                  >
                    <Avatar alt="Travis Howard" src="/static/images/avatar/2.jpg" />
                  </Badge>
                  <div style={{ marginLeft: '20px' }}>
                    <Typography variant="subtitle1">
                      {t('21 June 2021')}
                    </Typography>
                    Lorem Ipsum Dolor Ist
                  </div>
                </div>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 25 }}
                >
                  {t('Decision Maker')}
                </Typography>
                <div className="clearfix" />
                <div style={{ display: 'flex' }}>
                  <Badge
                    overlap="circular"
                    anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
                    badgeContent={
                      <Avatar style={{ width: 15, height: 15, backgroundColor: 'green' }} alt="Remy Sharp" />
                    }
                  >
                    <Avatar alt="Travis Howard" src="/static/images/avatar/2.jpg" />
                  </Badge>
                  <div style={{ marginLeft: '20px' }}>
                    <Typography variant="subtitle1">
                      {t('Lorem Ipsum')}
                    </Typography>
                    {t('Lorem Ipsum Dono Ist')}
                  </div>
                </div>
              </div>
              <div style={{ marginBottom: '10px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 30 }}
                >
                  {t('Last Modified')}
                </Typography>
                <div className="clearfix" />
                {t('June 11 2021')}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Lifecycle')}
                </Typography>
                <div className="clearfix" />
                <Button variant="outlined" color="primary" >Recommended</Button>
              </div>
            </Grid>
          </Grid>
          <Grid xs={12}>
            <Typography
              variant="h3"
              color="textSecondary"
              gutterBottom={true}
              style={{ float: 'left', marginTop: 30 }}
            >
              {t('Description')}
            </Typography>
            <div className="clearfix" />
            <div className={classes.scrollBg}>
              <div className={classes.scrollDiv}>
                <div className={classes.scrollObj}>
                  {/* {device.locations && device.locations.map((location, key) => (
                    <div key={key}>
                      {`${location.street_address && t(location.street_address)}, `}
                      {`${location.city && t(location.city)}, `}
  {`${location.country && t(location.country)}, ${location.postal_code && t(location.postal_code)}`}
                    </div>
                  ))} */}
                  {t('Description')}
                </div>
              </div>
            </div>
          </Grid>
        </Paper>
      </div>
    );
  }
}

RemediationGeneralOverviewComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const RemediationGeneralOverview = createFragmentContainer(
  RemediationGeneralOverviewComponent,
  {
    risk: graphql`
      fragment RemediationGeneralOverview_risk on ComputingDeviceAsset {
        id
        asset_id
        asset_type
        asset_tag
        description
        version
        vendor_name
        serial_number
        release_date
        # responsible_parties
        operational_status
        labels
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RemediationGeneralOverview);
