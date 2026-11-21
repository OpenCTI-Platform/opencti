import React, { Suspense, FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { styled } from '@mui/material/styles';
import ProfileOverview from './ProfileOverview';
import Loader, { LoaderVariant } from '../../../components/Loader';
import type { ProfileQuery } from './__generated__/ProfileQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const Container = styled('div')({
  margin: 0,
});

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
    themes(orderBy: created_at, orderMode: desc) {
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
  const data = usePreloadedQuery<ProfileQuery>(profileQuery, queryRef);
  const { me, about, settings, themes } = data;
  return (
    <Container>
      <Suspense fallback={<Loader />}>
        <ProfileOverview me={me} about={about} settings={settings} themes={themes} />
      </Suspense>
    </Container>
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
