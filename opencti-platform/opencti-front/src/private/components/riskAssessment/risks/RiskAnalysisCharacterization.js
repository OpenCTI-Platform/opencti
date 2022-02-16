import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  pathOr,
  map,
  path,
  mergeAll,
  pipe,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Table from '@material-ui/core/Table';
import LaunchIcon from '@material-ui/icons/Launch';
import Grid from '@material-ui/core/Grid';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Chip from '@material-ui/core/Chip';
import { InformationOutline, Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const styles = (theme) => ({
  paper: {
    height: '506px',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '0 24px',
    borderRadius: 6,
    overflowY: 'scroll',
  },
  header: {
    borderBottom: '1px solid white',
    padding: '22px 0 13px 0',
  },
  headerText: {
    paddingLeft: '16px',
    textTransform: 'capitalize',
  },
  tableText: {
    padding: '20px 0 20px 16px',
    textTransform: 'capitalize',
  },
});

class RiskAnalysisCharacterizationComponent extends Component {
  render() {
    const {
      t, fldt, classes, risk,
    } = this.props;
    const riskAnalysisCharacterization = pathOr([], ['characterizations'], risk);
    // const riskcharacterizationfacets = pathOr([], [], riskAnalysisCharacterization);
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Characterization')}
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
        <Paper className={classes.paper} elevation={2}>
          <Grid container={true} className={ classes.header}>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={ classes.headerText }
              >
                {t('Name')}
              </Typography>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={ classes.headerText }
              >
                {t('Value')}
              </Typography>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={ classes.headerText }
              >
                {t('Detection Source')}
              </Typography>
            </Grid>
          </Grid>
          {riskAnalysisCharacterization.map((characterizationData) => {
            const detectionSource = pipe(
              pathOr([], ['origins']),
              mergeAll,
              path(['origin_actors']),
              mergeAll,
            )(characterizationData);
            const characterizationFacets = pipe(
              pathOr([], ['facets']),
              mergeAll,
            )(characterizationData);
            console.log('RiskAnalysisCharacterizationData', characterizationFacets);
            return (
              <Grid key={characterizationData.id} container={true} style={{ borderBottom: '1px solid grey' }}>
                <Grid item={true} xs={4}>
                  <Typography
                    variant="h2"
                    gutterBottom={true}
                    className={ classes.tableText }
                  >
                    {characterizationFacets.cvss2_name
                    || characterizationFacets.cvss3_name
                    || characterizationFacets.risk_name
                    || characterizationFacets.vuln_name
                    || characterizationFacets.name}
                  </Typography>
                </Grid>
                <Grid item={true} xs={4}>
                  <Typography
                    variant="h2"
                    gutterBottom={true}
                    className={ classes.tableText }
                  >
                    {characterizationFacets?.value && t(characterizationFacets?.value)}
                  </Typography>
                </Grid>
                <Grid item={true} xs={4}>
                  <Typography
                    variant="h2"
                    gutterBottom={true}
                    className={ classes.tableText }
                  >
                    {detectionSource.actor.name && t(detectionSource.actor.name)}
                  </Typography>
                </Grid>
              </Grid>
            );
          })}
        </Paper>
      </div>
    );
  }
}

RiskAnalysisCharacterizationComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const RiskAnalysisCharacterization = createFragmentContainer(
  RiskAnalysisCharacterizationComponent,
  {
    risk: graphql`
      fragment RiskAnalysisCharacterization_risk on Risk {
        id
        created
        modified
        characterizations {
          id
          origins{
            id
            origin_actors {
              actor_type
              actor {
                ... on Component {
                  id
                  component_type
                  name          # Detection Source
                }
                ... on OscalParty {
                id
                party_type
                name            # Detection Source
                }
              }
            }
          }
          facets {
            id
            risk_state
            source_system
            ... on CustomFacet {
              name
              value
            }
            ... on RiskFacet {
              risk_name: name
              value
            }
            ... on VulnerabilityFacet {
              vuln_name: name
              value
            }
            ... on Cvss2Facet {
              cvss2_name: name
              value
            }
            ... on Cvss3Facet {
              cvss3_name: name
              value
            }
          }
        }
        links {
          id
          created
          modified
          external_id     # external id
          source_name     # Title
          description     # description
          url             # URL
          media_type      # Media Type
        }
        remarks {
          id
          abstract
          content
          authors
          labels {
            id
            name
            color
            description
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RiskAnalysisCharacterization);
