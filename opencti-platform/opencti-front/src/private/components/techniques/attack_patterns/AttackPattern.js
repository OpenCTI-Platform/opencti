import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import AttackPatternOverview from './AttackPatternOverview';
import AttackPatternDetails from './AttackPatternDetails';
import AttackPatternEdition from './AttackPatternEdition';
import AttackPatternPopover from './AttackPatternPopover';
import EntityExternalReferences from '../../common/external_references/EntityExternalReferences';
import EntityCoursesOfAction from '../courses_of_action/EntityCoursesOfAction';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityStixRelationsChart from '../../common/stix_relations/EntityStixRelationsChart';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class AttackPatternComponent extends Component {
  render() {
    const { classes, attackPattern } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={attackPattern}
          PopoverComponent={<AttackPatternPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={4}>
            <AttackPatternOverview attackPattern={attackPattern} />
          </Grid>
          <Grid item={true} xs={4}>
            <AttackPatternDetails attackPattern={attackPattern} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityExternalReferences entityId={attackPattern.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
        >
          <Grid item={true} xs={4}>
            <EntityCoursesOfAction entityId={attackPattern.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityStixRelationsChart
              entityId={attackPattern.id}
              relationType="uses"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={attackPattern.id} />
          </Grid>
        </Grid>
        <AttackPatternEdition attackPatternId={attackPattern.id} />
      </div>
    );
  }
}

AttackPatternComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const AttackPattern = createFragmentContainer(AttackPatternComponent, {
  attackPattern: graphql`
    fragment AttackPattern_attackPattern on AttackPattern {
      id
      name
      alias
      ...AttackPatternOverview_attackPattern
      ...AttackPatternDetails_attackPattern
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(AttackPattern);
