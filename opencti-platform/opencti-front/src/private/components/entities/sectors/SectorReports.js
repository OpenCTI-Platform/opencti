import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import SectorHeader from './SectorHeader';
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

class SectorReportsComponent extends Component {
  render() {
    const { classes, sector } = this.props;
    return (
      <div className={classes.container}>
        <SectorHeader sector={sector} />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <EntityReports entityId={sector.id} />
        </Paper>
      </div>
    );
  }
}

SectorReportsComponent.propTypes = {
  sector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const SectorReports = createFragmentContainer(SectorReportsComponent, {
  sector: graphql`
    fragment SectorReports_sector on Sector {
      id
      ...SectorHeader_sector
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(SectorReports);
