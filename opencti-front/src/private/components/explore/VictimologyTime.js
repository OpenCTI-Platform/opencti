import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import EntityStixRelationsTableTime from '../stix_relation/EntityStixRelationsTableTime';
import EntityStixRelationsChart from '../stix_relation/EntityStixRelationsChart';
import EntityStixRelationsTable from '../stix_relation/EntityStixRelationsTable';
import { currentYear } from '../../../utils/Time';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class VictimologyTime extends Component {
  render() {
    const {
      classes, t, stixDomainEntity, inferred,
    } = this.props;
    const fourYearsAgo = currentYear() - 3;
    const yearsList = [];
    for (let i = currentYear(); i >= fourYearsAgo; i--) {
      yearsList.push(i);
    }
    return (
      <div className={classes.container}>
        <Grid
          container={true}
          spacing={3}
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
        <div className="clearfix" style={{ marginBottom: 20 }} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          {yearsList.map(year => (
            <Grid item={true} key={year} xs={6} style={{ marginBottom: 40 }}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginBottom: 10 }}
              >
                {t('Year')} {year}
              </Typography>
              <div style={{ float: 'left', width: '48%', height: '100%' }}>
                <EntityStixRelationsTable
                  entityId={stixDomainEntity.id}
                  entityType="Sector"
                  relationType="targets"
                  startDate={`${year}-01-01T00:00:00Z`}
                  endDate={`${year}-12-31T23:59:59Z`}
                  field="name"
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
              </div>
              <div style={{ float: 'right', width: '48%', height: '100%' }}>
                <EntityStixRelationsTable
                  entityId={stixDomainEntity.id}
                  entityType="Country"
                  relationType="targets"
                  startDate={`${year}-01-01T00:00:00Z`}
                  endDate={`${year}-12-31T23:59:59Z`}
                  field="name"
                  resolveInferences={inferred}
                  resolveRelationType="attributed-to"
                  resolveRelationRole="origin"
                  resolveViaTypes={[
                    {
                      entityType: 'Organization',
                      relationType: 'localization',
                      relationRole: 'localized',
                    },
                  ]}
                />
              </div>
            </Grid>
          ))}
        </Grid>
      </div>
    );
  }
}

VictimologyTime.propTypes = {
  stixDomainEntity: PropTypes.object,
  inferred: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(VictimologyTime);
