import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import IncidentHeader from './IncidentHeader';
import EntityReports from '../../reports/EntityReports';

const styles = () => ({
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

class IncidentReportsComponent extends Component {
  render() {
    const { classes, incident } = this.props;
    return (
      <div className={classes.container}>
        <IncidentHeader incident={incident} />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <EntityReports entityId={incident.id} />
        </Paper>
      </div>
    );
  }
}

IncidentReportsComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IncidentReports = createFragmentContainer(IncidentReportsComponent, {
  incident: graphql`
    fragment IncidentReports_incident on Incident {
      id
      ...IncidentHeader_incident
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(IncidentReports);
