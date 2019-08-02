import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import IntrusionSetHeader from './IntrusionSetHeader';
import Reports from '../../reports/Reports';

const styles = () => ({
  container: {
    margin: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class IntrusionSetReportsComponent extends Component {
  render() {
    const { classes, intrusionSet } = this.props;
    return (
      <div className={classes.container}>
        <IntrusionSetHeader intrusionSet={intrusionSet} />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Reports objectId={intrusionSet.id} />
        </Paper>
      </div>
    );
  }
}

IntrusionSetReportsComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSetReports = createFragmentContainer(
  IntrusionSetReportsComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetReports_intrusionSet on IntrusionSet {
        id
        ...IntrusionSetHeader_intrusionSet
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetReports);
