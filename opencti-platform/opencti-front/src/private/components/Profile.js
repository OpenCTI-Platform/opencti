import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
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
    about {
      ...ProfileOverview_about
    }
    settings {
      platform_modules {
        id
        enable
      }
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
              const subscriptionStatus = R.head(
                R.filter(
                  (n) => n.id === 'SUBSCRIPTION_MANAGER',
                  R.pathOr([], ['settings', 'platform_modules'], props),
                ),
              )?.enable;
              return (
                <ProfileOverview
                  me={props.me}
                  about={props.about}
                  subscriptionStatus={subscriptionStatus}
                />
              );
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

export default R.compose(inject18n, withStyles(styles))(Profile);
