import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import EntityStixRelationsPie from '../stix_relation/EntityStixRelationsPie';
import EntityStixRelationsTable from '../stix_relation/EntityStixRelationsTable';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class AttackPatternsDistribution extends Component {
  render() {
    const { classes, stixDomainEntity, inferred } = this.props;
    return (
      <div className={classes.container}>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <EntityStixRelationsTable
              entityId={stixDomainEntity.id}
              entityType="Attack-Pattern"
              relationType="uses"
              field="name"
              resolveInferences={inferred}
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
            />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityStixRelationsPie
              entityId={stixDomainEntity.id}
              entityType="Attack-Pattern"
              relationType="uses"
              field="name"
              resolveInferences={inferred}
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
            />
          </Grid>
        </Grid>
      </div>
    );
  }
}

AttackPatternsDistribution.propTypes = {
  stixDomainEntity: PropTypes.object,
  inferred: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AttackPatternsDistribution);
