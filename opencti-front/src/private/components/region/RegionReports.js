import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../components/i18n';
import RegionHeader from './RegionHeader';
import EntityReports from '../report/EntityReports';

const styles = theme => ({
  container: {
    margin: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

class RegionReportsComponent extends Component {
  render() {
    const { classes, region } = this.props;
    return (
      <div className={classes.container}>
        <RegionHeader region={region}/>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <EntityReports entityId={region.id}/>
        </Paper>
      </div>
    );
  }
}

RegionReportsComponent.propTypes = {
  region: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const RegionReports = createFragmentContainer(RegionReportsComponent, {
  region: graphql`
      fragment RegionReports_region on Region {
          id
          ...RegionHeader_region
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(RegionReports);
