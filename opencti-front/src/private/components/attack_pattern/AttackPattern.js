import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import AttackPatternHeader from './AttackPatternHeader';
import AttackPatternOverview from './AttackPatternOverview';
import AttackPatternEdition from './AttackPatternEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityRelationsChart from '../stix_relation/EntityRelationsChart';
import EntityReportsChart from '../report/EntityReportsChart';
import AttackPatternUsageChart from './AttackPatternUsageChart';

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
        <AttackPatternHeader attackPattern={attackPattern}/>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={6}>
            <AttackPatternOverview attackPattern={attackPattern}/>
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={attackPattern.id}/>
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }} style={{ marginTop: 20 }}>
          <Grid item={true} xs={4}>
            <AttackPatternUsageChart attackPatternId={attackPattern.id}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityRelationsChart entityId={attackPattern.id}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={attackPattern.id}/>
          </Grid>
        </Grid>
        <AttackPatternEdition attackPatternId={attackPattern.id}/>
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
          ...AttackPatternHeader_attackPattern
          ...AttackPatternOverview_attackPattern
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(AttackPattern);
