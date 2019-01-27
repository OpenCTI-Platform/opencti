import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import IntrusionSetHeader from './IntrusionSetHeader';
import EntityReports from '../report/EntityReports';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class IntrusionSetReportsComponent extends Component {
  render() {
    const { classes, intrusionSet } = this.props;
    return (
      <div className={classes.container}>
        <IntrusionSetHeader intrusionSet={intrusionSet}/>
        <div style={{ height: 20 }}/>
        <EntityReports entityId={intrusionSet.id}/>
      </div>
    );
  }
}

IntrusionSetReportsComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSetReports = createFragmentContainer(IntrusionSetReportsComponent, {
  intrusionSet: graphql`
      fragment IntrusionSetReports_intrusionSet on IntrusionSet {
          id
          ...IntrusionSetHeader_intrusionSet
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetReports);
