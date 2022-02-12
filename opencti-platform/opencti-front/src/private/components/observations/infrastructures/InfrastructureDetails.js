import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class InfrastructureDetailsComponent extends Component {
  render() {
    const { t, fld, classes, infrastructure } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('First seen')}
              </Typography>
              {fld(infrastructure.first_seen)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Last seen')}
              </Typography>
              {fld(infrastructure.last_seen)}
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
                {t('Kill chain phases')}
              </Typography>
              fdf
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
        first_seen
        last_seen
        creator {
          id
          name
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
