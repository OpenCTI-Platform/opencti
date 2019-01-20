import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import ReportHeader from './ReportHeader';
import AddStixDomains from '../stix_domain/AddStixDomains';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class ReportComponent extends Component {
  render() {
    const { classes, report } = this.props;
    return (
      <div className={classes.container}>
        <ReportHeader report={report}/>

      </div>
    );
  }
}

ReportComponent.propTypes = {
  reportId: PropTypes.string.isRequired,
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Report = createFragmentContainer(ReportComponent, {
  report: graphql`
      fragment Report_report on Report {
          ...ReportHeader_report
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Report);
