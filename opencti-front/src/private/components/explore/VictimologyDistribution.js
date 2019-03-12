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

class VictimologyDistribution extends Component {
  render() {
    const { classes, t, stixDomainEntity } = this.props;
    return (
      <div className={classes.container}>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={6}>
            <EntityStixRelationsTable
              entityId={stixDomainEntity.id}
              entityType='Sector'
              relationType='targets'
              field='name'
              resolveInferences={true}
              resolveRelationType='attributed-to'
              resolveRelationRole='origin'
              resolveViaTypes={[
                { entityType: 'Organization', relationType: 'gathering', relationRole: 'part_of' },
                { entityType: 'Organization', relationType: 'localization', relationRole: 'localized' },
                { entityType: 'Country', relationType: 'localization', relationRole: 'localized' },
              ]}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityStixRelationsTable
              entityId={stixDomainEntity.id}
              entityType='Region'
              relationType='targets'
              field='name'
              resolveInferences={true}
              resolveRelationType='attributed-to'
              resolveRelationRole='origin'
            />
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} style={{ marginTop: 50 }}>
          <Grid item={true} xs={6}>
            <EntityStixRelationsPie
              entityId={stixDomainEntity.id}
              entityType='Sector'
              relationType='targets'
              field='name'
              resolveInferences={true}
              resolveRelationType='attributed-to'
              resolveRelationRole='origin'
              resolveViaTypes={[
                { entityType: 'Organization', relationType: 'gathering', relationRole: 'part_of' },
                { entityType: 'Organization', relationType: 'localization', relationRole: 'localized' },
                { entityType: 'Country', relationType: 'localization', relationRole: 'localized' },
              ]}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityStixRelationsPie
              entityId={stixDomainEntity.id}
              entityType='Region'
              relationType='targets'
              field='name'
              resolveInferences={true}
              resolveRelationType='attributed-to'
              resolveRelationRole='origin'
            />
          </Grid>
        </Grid>
      </div>
    );
  }
}

VictimologyDistribution.propTypes = {
  stixDomainEntity: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(VictimologyDistribution);
