/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pipe, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import Typography from '@material-ui/core/Typography';
import { Grid } from '@material-ui/core';
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

class EntityResponsiblePartyDetailsComponent extends Component {
  render() {
    const {
      t,
      classes,
      refreshQuery,
      responsibleParty,
      fldt,
      history,
    } = this.props;
    const partyData = pipe(
      pathOr([], ['parties']),
    )(responsibleParty);
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
                {partyData.length > 0 && partyData.map((party) => (party.name))}
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
                {responsibleParty?.created && fldt(responsibleParty?.created)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Role')}
                </Typography>
                <div className="clearfix" />
                {responsibleParty?.role && t(responsibleParty.role.role_identifier)}
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
                {responsibleParty.id && t(responsibleParty.id)}
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
                {responsibleParty?.modified && fldt(responsibleParty?.modified)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Parties')}
                </Typography>
                <div className="clearfix" />
                <div style={{ height: '100px', overflowY: 'scroll' }}>
                  {responsibleParty?.parties.length > 0
                    && responsibleParty.parties.map((value) => (
                      <Typography>
                        {t(value.name)}
                      </Typography>
                    ))}
                </div>
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
                      {responsibleParty?.description && t(responsibleParty?.description)}
                    </Markdown>
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={3}>
              <CyioCoreObjectLabelsView
                labels={responsibleParty.labels}
                marginTop={0}
                refreshQuery={refreshQuery}
                id={responsibleParty.id}
                typename={responsibleParty.__typename}
              />
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
              >
                {t('Markings')}
              </Typography>
              <div className="clearfix" />
              {responsibleParty?.markings && (
                <p className={classes.markingText}>
                  {t(responsibleParty?.markings)}
                </p>
              )}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

EntityResponsiblePartyDetailsComponent.propTypes = {
  responsibleParty: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const EntityResponsiblePartyDetails = createFragmentContainer(
  EntityResponsiblePartyDetailsComponent,
  {
    responsibleParty: graphql`
      fragment EntityResponsiblePartyDetails_responsibleParty on OscalResponsibleParty {
        __typename
        id
        entity_type
        role {
          id
          entity_type
          role_identifier
        }
        parties {
          id
          entity_type
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

export default compose(inject18n, withStyles(styles))(EntityResponsiblePartyDetails);
