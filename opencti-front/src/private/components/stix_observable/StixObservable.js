import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import StixObservableHeader from './StixObservableHeader';
import StixObservableOverview from './StixObservableOverview';
import StixObservableEdition from './StixObservableEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityStixRelationsChart from '../stix_relation/EntityStixRelationsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class StixObservableComponent extends Component {
  render() {
    const { classes, stixObservable } = this.props;
    return (
      <div className={classes.container}>
        <StixObservableHeader stixObservable={stixObservable} />
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <StixObservableOverview stixObservable={stixObservable} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={stixObservable.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 20 }}
        >
          <Grid item={true} xs={4}>
            <EntityStixRelationsChart
              entityId={stixObservable.id}
              relationType="uses"
              resolveInferences={true}
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
            />
          </Grid>
          <Grid item={true} xs={4}>
            &nbsp;
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={stixObservable.id} />
          </Grid>
        </Grid>
        <StixObservableEdition stixObservableId={stixObservable.id} />
      </div>
    );
  }
}

StixObservableComponent.propTypes = {
  stixObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const StixObservable = createFragmentContainer(StixObservableComponent, {
  stixObservable: graphql`
    fragment StixObservable_stixObservable on StixObservable {
      id
      ...StixObservableHeader_stixObservable
      ...StixObservableOverview_stixObservable
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservable);
