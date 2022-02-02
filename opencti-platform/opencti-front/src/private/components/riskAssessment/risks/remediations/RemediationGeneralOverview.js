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
      t,
      fd,
      fldt,
      classes,
      remediation,
    } = this.props;
    console.log('remediationGenreal', remediation);
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        {/*  <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {remediation.objectMarking.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
              remediation.objectMarking.edges,
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
          {fldt(remediation.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(remediation.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', remediation)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={remediation.description}
            limit={250}
          />
        </Paper> */}
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div style={{ marginBottom: '25px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Name')}
                </Typography>
                <div className="clearfix" />
                {/* {t('Lorem Ipsum Dolor Sit Amet')} */}
                {remediation.name && t(remediation.name)}
              </div>
              <div style={{ marginBottom: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Created')}
                </Typography>
                <div className="clearfix" />
                {/* {t('Lorem Ipsum Dolor Sit Amet')} */}
                {remediation.created && fd(remediation.created)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div style={{ marginBottom: '25px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('ID')}
                </Typography>
                <div className="clearfix" />
                {remediation.id && t(remediation.id)}
              </div>
              <div style={{ marginBottom: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Last Modified')}
                </Typography>
                <div className="clearfix" />
                {/* {t('June 11 2021')} */}
                {remediation.modified && fd(remediation.modified)}
              </div>
            </Grid>
          </Grid>
          <Grid xs={12}>
            <Typography
              variant="h3"
              color="textSecondary"
              gutterBottom={true}
              style={{ float: 'left' }}
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
                  {/* {t('Description')} */}
                  {remediation.description && t(remediation.description)}
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
  remediation: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const RemediationGeneralOverview = createFragmentContainer(
  RemediationGeneralOverviewComponent,
  {
    remediation: graphql`
      fragment RemediationGeneralOverview_remediation on RiskResponse {
        id
        name                # Title
        description         # Description
        created             # Created
        modified            # Last Modified
        lifecycle           # Lifecycle
        response_type       # Response Type
        origins{
          id
          origin_actors {
            actor_type
            actor {
              ... on OscalPerson {
                id
                name        #Source
              }
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RemediationGeneralOverview);
