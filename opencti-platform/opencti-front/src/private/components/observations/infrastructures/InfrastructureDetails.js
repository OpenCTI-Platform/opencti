import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { Launch } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import Chip from '@mui/material/Chip';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';

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
              {propOr(['-'], 'infrastructure_types', infrastructure).map(
                (infrastructureType) => (
                  <Chip
                    key={infrastructureType}
                    classes={{ root: classes.chip }}
                    label={infrastructureType}
                  />
                ),
              )}
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
              {fldt(infrastructure.first_seen)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Last seen')}
              </Typography>
              {fldt(infrastructure.last_seen)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Kill chain phases')}
              </Typography>
              <List>
                {infrastructure.killChainPhases.edges.map(
                  (killChainPhaseEdge) => {
                    const killChainPhase = killChainPhaseEdge.node;
                    return (
                      <ListItem
                        key={killChainPhase.phase_name}
                        dense={true}
                        divider={true}
                        classes={{ root: classes.item }}
                      >
                        <ListItemIcon classes={{ root: classes.itemIcon }}>
                          <Launch />
                        </ListItemIcon>
                        <ListItemText primary={killChainPhase.phase_name} />
                      </ListItem>
                    );
                  },
                )}
              </List>
            </Grid>
          </Grid>
          <br />
          <EntityStixCoreRelationshipsDonut
            variant="inEntity"
            entityId={infrastructure.id}
            toTypes={['Stix-Cyber-Observable']}
            relationshipType="consists-of"
            field="entity_type"
            height={260}
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
        creator {
          id
          name
        }
        killChainPhases {
          edges {
            node {
              id
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
