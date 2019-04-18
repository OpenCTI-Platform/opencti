import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import EntityStixRelationsTableTime from '../stix_relation/EntityStixRelationsTableTime';
import EntityStixRelationsChart from '../stix_relation/EntityStixRelationsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class AttackPatternsTime extends Component {
  render() {
    const {
      classes, t, stixDomainEntity, inferred,
    } = this.props;
    return (
      <div className={classes.container}>
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={4}>
            <EntityStixRelationsTableTime
              title={t('Number of targeting')}
              entityId={stixDomainEntity.id}
              relationType="targets"
              resolveInferences={inferred}
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              resolveViaTypes={[
                {
                  entityType: 'Organization',
                  relationType: 'gathering',
                  relationRole: 'part_of',
                },
              ]}
            />
          </Grid>
          <Grid item={true} xs={8}>
            <EntityStixRelationsChart
              title={t('Targeted entities through time')}
              entityId={stixDomainEntity.id}
              relationType="targets"
              resolveInferences={inferred}
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              resolveViaTypes={[
                {
                  entityType: 'Organization',
                  relationType: 'gathering',
                  relationRole: 'part_of',
                },
              ]}
            />
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} style={{ marginTop: 30 }} />
      </div>
    );
  }
}

AttackPatternsTime.propTypes = {
  stixDomainEntity: PropTypes.object,
  inferred: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AttackPatternsTime);
