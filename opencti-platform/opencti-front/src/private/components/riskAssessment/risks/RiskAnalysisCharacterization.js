import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr, map } from 'ramda';
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
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '0 24px',
    borderRadius: 6,
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
    console.log('RiskAnalysisCharacterizationContainer', risk);
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
          <Grid container={true} style={{ borderBottom: '1px solid grey' }}>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={ classes.tableText }
              >
                {t('Lorem Ipsum')}
              </Typography>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={ classes.tableText }
              >
                {t('Lorem Ipsum')}
              </Typography>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={ classes.tableText }
              >
                {t('Lorem Ipsum')}
              </Typography>
            </Grid>
          </Grid>
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
          ... on VulnerabilityCharacterization {
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
            vulnerability_id
            exploitability
            exploitability
            severity
            cvss3_vector_string
            cvss3_base_score
            cvss3_temporal_score
            cvss3_environmental_score
            cvss2_vector_string
            cvss2_base_score
            cvss2_temporal_score
            cvss2_environmental_score
            score_rationale
            facets {
              id
              risk_state
              name            # Characterization Name
              value           # Characterization Value
            }
          }
          ... on RiskCharacterization {
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
            risk
            likelihood
            impact
            facets {
              id
              risk_state
              name            # Characterization Name
              value           # Characterization Value
            }
          }
        }
        # external_references {
          # id
          # created
          # modified
          # external_id     # external id
          # source_name     # Title
          # description     # description
          # url             # URL
          # media_type      # Media Type
        # }
        # notes {
        #   id
        #   abstract
        #   content
        #   authors
        #   labels {
        #     id
        #     name
        #     color
        #     description
        #   }
        # }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RiskAnalysisCharacterization);
