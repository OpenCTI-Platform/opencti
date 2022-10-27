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
import { Grid } from '@material-ui/core';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import remarkParse from 'remark-parse';
import inject18n from '../../../../../components/i18n';
import CyioCoreObjectLabelsView from '../../../common/stix_core_objects/CyioCoreObjectLabelsView';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 0 24px',
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
  },
});

class DataSourceDetailsComponent extends Component {
  render() {
    const {
      t,
      classes,
      refreshQuery,
      location,
      fldt,
      history,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
        <Grid container={true}>
          <Grid container item xs={8} spacing={1}>
            <Grid container item xs={12} spacing={1}>
              <Grid item xs={6}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Name')}
                  </Typography>
                  <div className="clearfix" />
                  {location.name && t(location.name)}
                </div>
              </Grid>
              <Grid item xs={6}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('ID')}
                  </Typography>
                  <div className="clearfix" />
                  {location.id && t(location.id)}
                </div>
              </Grid>
            </Grid>
            <Grid container item xs={12} spacing={1}>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Created')}
                  </Typography>
                  <div className="clearfix" />
                  {location.created && fldt(location.created)}
                </div>
              </Grid>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Last Modified')}
                  </Typography>
                  <div className="clearfix" />
                  {location.modified && fldt(location.modified)}
                </div>
              </Grid>
            </Grid>
            <Grid container item xs={12} spacing={1}>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Street Address')}
                  </Typography>
                  <div className="clearfix" />
                  {location?.address?.street_address && t(location?.address?.street_address)}
                </div>
              </Grid>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Administrative Area')}
                  </Typography>
                  <div className="clearfix" />
                  {location?.address?.administrative_area && t(location?.address?.administrative_area)}
                </div>
              </Grid>
            </Grid>            
            <Grid container item xs={12} spacing={1}>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Country')}
                  </Typography>
                  <div className="clearfix" />
                  {location?.address?.country_code && t(location?.address?.country_code)}
                </div>
              </Grid>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Postal Code')}
                  </Typography>
                  <div className="clearfix" />
                  {location?.address?.postal_code && t(location?.address?.postal_code)}
                </div>
              </Grid>
            </Grid>
            <Grid container item xs={12} spacing={1}>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Telephone Number')}
                  </Typography>
                  <div className="clearfix" />
                  {location?.telephone_numbers && location?.telephone_numbers.length > 0 && 
                    location?.telephone_numbers.map(
                      (number) => <div>{t(number?.phone_number)}</div>
                    )
                  }
                </div>
              </Grid>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Email Address(es)')}
                  </Typography>
                  <div className="clearfix" />
                  {location?.email_addresses && location?.email_addresses.length > 0 && 
                    location?.email_addresses.map(
                      (email) => <div>{t(email)}</div>
                    )
                  }
                </div>
              </Grid>
            </Grid>
            <Grid container item xs={12} spacing={1}>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Location Type')}
                  </Typography>
                  <div className="clearfix" />
                  {location?.location_type && t(location?.location_type)}
                </div>
              </Grid>
              <Grid item xs={6}>
                <div style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Location Class')}
                  </Typography>
                  <div className="clearfix" />
                  {location?.location_class && t(location?.location_class)}
                </div>
              </Grid>
            </Grid>
            <Grid container item xs={12} spacing={1} style={{ marginTop: '25%' }}>
              <Grid item={true} xs={6}>
                <CyioCoreObjectLabelsView
                  labels={location.labels}
                  marginTop={0}
                  refreshQuery={refreshQuery}
                  id={location.id}
                  typename={location.__typename}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Markings')}
                </Typography>
                <div className="clearfix" />
                {
                  location?.markings && (
                    <p className={classes.markingText}>
                      {t(location?.markings)}
                    </p>
                  )
                }
              </Grid>
            </Grid>
          </Grid>
          <Grid container item={true} xs={4} spacing={3}>
            <Grid item={true} xs={12}>
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
                      rehypePlugins={[rehypeRaw]}
                      parserOptions={{ commonmark: true }}
                      className="markdown"
                    >
                      {location.description && t(location.description)}
                    </Markdown>
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

DataSourceDetailsComponent.propTypes = {
  location: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const DataSourceDetails = createFragmentContainer(
  DataSourceDetailsComponent,
  {
    location: graphql`
      fragment DataSourceDetails_location on OscalLocation {
        __typename
        id
        entity_type
        created
        modified
        name
        description
        location_type
        location_class
        address {
          id
          address_type
          street_address
          city
          administrative_area
          country_code
          postal_code
        }
        email_addresses
        telephone_numbers {
          id
          usage_type
          phone_number
        }
        urls 
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

export default compose(inject18n, withStyles(styles))(DataSourceDetails);
