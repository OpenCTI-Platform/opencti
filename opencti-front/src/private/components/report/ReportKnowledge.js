import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
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
        <AddStixDomains entityId={propOr(null, 'id', report)} entityStixDomains={[]} />
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
      fragment ReportKnowledge_report on Report {
          ...ReportHeader_report
          id
          name
          objectRefs {
              edges {
                  node {
                      id
                      type
                      name
                  }
              }
          }
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Report);
