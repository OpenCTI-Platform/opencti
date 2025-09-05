import React, { Suspense, FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import ProfileOverview from './ProfileOverview';
import Loader, { LoaderVariant } from '../../../components/Loader';
import type { ProfileQuery } from './__generated__/ProfileQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    }
    themes {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface ProfileComponentProps {
  queryRef: PreloadedQuery<ProfileQuery>;
}

const ProfileComponent: FunctionComponent<ProfileComponentProps> = ({
  queryRef,
}) => {
  const classes = useStyles();
  const data = usePreloadedQuery<ProfileQuery>(profileQuery, queryRef);
  const { me, about, settings, themes } = data;
  return (
    <div className={classes.container}>
      <Suspense fallback={<Loader />}>
        <ProfileOverview me={me} about={about} settings={settings} themes={themes} />
      </Suspense>
    </div>
  );
};

const Profile: FunctionComponent = () => {
  const queryRef = useQueryLoading<ProfileQuery>(profileQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ProfileComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default Profile;
