import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import PersonHeader from './PersonHeader';
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

class PersonReportsComponent extends Component {
  render() {
    const { classes, person } = this.props;
    return (
      <div className={classes.container}>
        <PersonHeader person={person} />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Reports objectId={person.id} />
        </Paper>
      </div>
    );
  }
}

PersonReportsComponent.propTypes = {
  person: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const PersonReports = createFragmentContainer(PersonReportsComponent, {
  person: graphql`
    fragment PersonReports_person on User {
      id
      ...PersonHeader_person
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(PersonReports);
