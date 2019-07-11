import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../components/i18n';
import AttackPatternHeader from './AttackPatternHeader';
import EntityReports from '../report/EntityReports';

const styles = theme => ({
  container: {
    margin: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class AttackPatternReportsComponent extends Component {
  render() {
    const { classes, attackPattern } = this.props;
    return (
      <div className={classes.container}>
        <AttackPatternHeader attackPattern={attackPattern} />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <EntityReports entityId={attackPattern.id} />
        </Paper>
      </div>
    );
  }
}

AttackPatternReportsComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const AttackPatternReports = createFragmentContainer(
  AttackPatternReportsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternReports_attackPattern on AttackPattern {
        id
        ...AttackPatternHeader_attackPattern
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(AttackPatternReports);
