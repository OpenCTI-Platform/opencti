import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import { List } from '@mui/material';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: '0',
    margin: '0 5px 5px 0',
  },
});

class InfrastructureDetailsComponent extends Component {
  render() {
    const { t, fldt, classes, infrastructure } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Infrastructure types')}
              </Typography>
              {infrastructure.infrastructure_types && infrastructure.infrastructure_types.length > 0
                ? <List>{
                  infrastructure.infrastructure_types.map(
                    (infrastructureType) => (
                      <Chip
                        key={infrastructureType}
                        classes={{ root: classes.chip }}
                        label={infrastructureType}
                      />
                    ),
                  )
                }
                </List>
                : ('-')}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown
                source={infrastructure.description}
                limit={400}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('First seen')}
              </Typography>
              {infrastructure.first_seen ? fldt(infrastructure.first_seen) : ('-')}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Last seen')}
              </Typography>
              {infrastructure.last_seen ? fldt(infrastructure.last_seen) : ('-')}
            </Grid>
            <Grid item={true} xs={6}>
              <StixCoreObjectKillChainPhasesView killChainPhasesEdges={infrastructure.killChainPhases.edges} />
            </Grid>
          </Grid>
          <br />
          <EntityStixCoreRelationshipsDonut
            variant="inEntity"
            fromId={infrastructure.id}
            toTypes={['Stix-Cyber-Observable']}
            relationshipType="consists-of"
            field="entity_type"
            height={260}
            isTo={true}
          />
        </Paper>
      </div>
    );
  }
}

InfrastructureDetailsComponent.propTypes = {
  infrastructure: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const InfrastructureDetails = createFragmentContainer(
  InfrastructureDetailsComponent,
  {
    infrastructure: graphql`
      fragment InfrastructureDetails_infrastructure on Infrastructure {
        id
        name
        description
        infrastructure_types
        first_seen
        last_seen
        killChainPhases {
          edges {
            node {
              id
              entity_type
              kill_chain_name
              phase_name
              x_opencti_order
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(InfrastructureDetails);
