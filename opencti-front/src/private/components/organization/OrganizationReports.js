import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import OrganizationHeader from './OrganizationHeader';
import EntityReports from '../report/EntityReports';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class OrganizationReportsComponent extends Component {
  render() {
    const { classes, organization } = this.props;
    return (
      <div className={classes.container}>
        <OrganizationHeader organization={organization}/>
        <div style={{ height: 20 }}/>
        <EntityReports entityId={organization.id}/>
      </div>
    );
  }
}

OrganizationReportsComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const OrganizationReports = createFragmentContainer(OrganizationReportsComponent, {
  organization: graphql`
      fragment OrganizationReports_organization on Organization {
          id
          ...OrganizationHeader_organization
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(OrganizationReports);
