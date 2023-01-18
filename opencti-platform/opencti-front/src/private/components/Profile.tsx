import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import ProfileOverview from './profile/ProfileOverview';
import Loader from '../../components/Loader';
import type { ProfileQuery } from './__generated__/ProfileQuery.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

export const profileQuery = graphql`
  query ProfileQuery {
    me {
      ...ProfileOverview_me
    }
    about {
      ...ProfileOverview_about
    }
    settings {
      ...ProfileOverview_settings
      platform_modules {
        id
        enable
        running
      }
      otp_mandatory
    }
  }
`;

const Profile = () => {
  const classes = useStyles();
  const data = useLazyLoadQuery<ProfileQuery>(profileQuery, {});
  const { me, about, settings } = data;
  const modules = settings?.platform_modules ?? [];
  const subscriptionStatus = modules.find(
    (m) => m.id === 'SUBSCRIPTION_MANAGER',
  )?.enable;
  return (
    <div className={classes.container}>
      <Suspense fallback={<Loader />}>
        <ProfileOverview
          me={me}
          about={about}
          settings={settings}
          subscriptionStatus={subscriptionStatus}
        />
      </Suspense>
    </div>
  );
};

export default Profile;
