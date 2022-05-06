/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { Grid, Tooltip } from '@material-ui/core';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { Information } from 'mdi-material-ui';
import inject18n from '../../../../../components/i18n';
import CyioCoreObjectLabelsView from '../../../common/stix_core_objects/CyioCoreObjectLabelsView';
const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  link: {
    textAlign: 'left',
    fontSize: '16px',
    font: 'DIN Next LT Pro',
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
    height: '223px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollAddressDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '150px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  markingText: {
    background: theme.palette.header.text,
    color: 'black',
    width: '100px',
    textAlign: 'center',
    padding: '3px 0',
  }
});

class EntityPartyDetailsComponent extends Component {
  render() {
    const {
      t,
      classes,
      refreshQuery,
      party,
      fldt,
      history,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={3}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Name')}
                </Typography>
                <div className="clearfix" />
                {party.name && t(party.name)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Created')}
                </Typography>
                <div className="clearfix" />
                {party.created && fldt(party.created)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Party Type')}
                </Typography>
                <div className="clearfix" />
                {party.party_type && t(party.party_type)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('External Identifiers')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('External Identifiers')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {party.external_identifiers && t(party.external_identifiers.map((value) => value.entity_type))}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Office')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Office')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {party.office && t(party.office)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Telephone Number')}
                </Typography>
                <div className="clearfix" />
                {party.telephone_numbers && t(party.telephone_numbers.map((number) => number.phone_number))}
              </div>
            </Grid>
            <Grid item={true} xs={4}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('ID')}
                </Typography>
                <div className="clearfix" />
                {party.id && t(party.id)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Last Modified')}
                </Typography>
                <div className="clearfix" />
                {party.modified && fldt(party.modified)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Job Title')}
                </Typography>
                <div className="clearfix" />
                {party.job_title && t(party.job_title)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Member Of')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Member of')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {party.member_of_organizations && t(party.member_of_organizations.map((value) => value.name))}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Mail Stop')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Mail Stop')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {party.mail_stop && t(party.mail_stop)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Email Address')}
                </Typography>
                <div className="clearfix" />
                {party.email_addresses && t(party.email_addresses.map((value) => value))}
              </div>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
              >
                {t('Description')}
              </Typography>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    <Markdown
                      remarkPlugins={[remarkGfm, remarkParse]}
                      parserOptions={{ commonmark: true }}
                      className="markdown"
                    >
                      {party.desctiption && t(party.desctiption)}
                    </Markdown>
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            {
              party.addresses.length > 0 ? (
                <Grid item={true} xs={5}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Address(es)')}
                  </Typography>
                  <div className="clearfix" />
                  <div className={classes.scrollBg}>
                    <div className={classes.scrollAddressDiv}>
                      <div className={classes.scrollObj}>
                        {party.addresses && t(party.addresses.map((value) => value.street_address))}
                      </div>
                    </div>
                  </div>
                </Grid>
              ) : (
                <Grid item={true} xs={5}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Location(s)')}
                  </Typography>
                  <div className="clearfix" />
                  <div className={classes.scrollBg}>
                    <div className={classes.scrollAddressDiv}>
                      <div className={classes.scrollObj}>
                        {party.locations && t(party.locations.map((value) => value.name))}
                      </div>
                    </div>
                  </div>
                </Grid>
              )
            }
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={3}>
              <div style={{ marginBottom: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Location Type')}
                </Typography>
                <div className="clearfix" />
                {party.locations && t(party.locations.map((value) => value.location_type))}
              </div>
              <CyioCoreObjectLabelsView
                labels={party.labels}
                marginTop={0}
                refreshQuery={refreshQuery}
                id={party.id}
                typename={party.__typename}
              />
            </Grid>
            <Grid item={true} xs={4}>
              <div style={{ marginBottom: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Location Class')}
                </Typography>
                <div className="clearfix" />
                {party.locations && t(party.locations.map((value) => value.location_class))}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Markings')}
                </Typography>
                <div className="clearfix" />
                {/* <p className={classes.markingText}>
              </p> */}
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

EntityPartyDetailsComponent.propTypes = {
  party: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const EntityPartyDetails = createFragmentContainer(
  EntityPartyDetailsComponent,
  {
    party: graphql`
      fragment EntityPartyDetails_party on OscalParty {
        __typename
        id
        created
        modified
        name
        description
        party_type
        email_addresses
        short_name
        mail_stop
        office
        job_title
        addresses {
          id
          address_type
          street_address
        }
        locations {
          id
          name
          location_type
          location_class
        }
        telephone_numbers {
          id
          usage_type
          phone_number
        }
        external_identifiers {
          id
          entity_type
        }
        member_of_organizations {
          id
          name
        }
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(EntityPartyDetails);
