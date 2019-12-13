import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import inject18n from '../../components/i18n';
import { QueryRenderer } from '../../relay/environment';
import ProfileOverview from './profile/ProfileOverview';
import Loader from '../../components/Loader';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const profileQuery = graphql`
  query ProfileQuery {
    me {
      ...ProfileOverview_me
    }
  }
`;

class Profile extends Component {
  render() {
    const { classes } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={profileQuery}
          render={({ props }) => {
            if (props) {
              return <ProfileOverview me={props.me} />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

Profile.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Profile);
