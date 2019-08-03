import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import CountryHeader from './CountryHeader';
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

class CountryReportsComponent extends Component {
  render() {
    const { classes, country } = this.props;
    return (
      <div className={classes.container}>
        <CountryHeader country={country} />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Reports objectId={country.id} />
        </Paper>
      </div>
    );
  }
}

CountryReportsComponent.propTypes = {
  country: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CountryReports = createFragmentContainer(CountryReportsComponent, {
  country: graphql`
    fragment CountryReports_country on Country {
      id
      ...CountryHeader_country
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(CountryReports);
