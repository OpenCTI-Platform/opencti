import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import IntrusionSetHeader from './IntrusionSetHeader';
import IntrusionSetOverview from './IntrusionSetOverview';
import IntrusionSetIdentity from './IntrusionSetIdentity';
import IntrusionSetEdition from './IntrusionSetEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityObservablesChart from '../observable/EntityObservablesChart';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityKillChainPhasesChart from '../kill_chain_phase/EntityKillChainPhasesChart';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class IntrusionSetComponent extends Component {
  render() {
    const { classes, intrusionSet } = this.props;
    return (
      <div className={classes.container}>
        <IntrusionSetHeader intrusionSet={intrusionSet}/>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={3}>
            <IntrusionSetOverview intrusionSet={intrusionSet}/>
          </Grid>
          <Grid item={true} xs={3}>
            <IntrusionSetIdentity intrusionSet={intrusionSet}/>
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={intrusionSet.id}/>
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }} style={{ marginTop: 20 }}>
          <Grid item={true} xs={4}>
            <EntityObservablesChart intrusionSet={intrusionSet}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityKillChainPhasesChart intrusionSet={intrusionSet}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart intrusionSet={intrusionSet}/>
          </Grid>
        </Grid>
        <IntrusionSetEdition intrusionSetId={intrusionSet.id}/>
      </div>
    );
  }
}

IntrusionSetComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSet = createFragmentContainer(IntrusionSetComponent, {
  intrusionSet: graphql`
      fragment IntrusionSet_intrusionSet on IntrusionSet {
          id
          ...IntrusionSetHeader_intrusionSet
          ...IntrusionSetOverview_intrusionSet
          ...IntrusionSetIdentity_intrusionSet
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(IntrusionSet);
