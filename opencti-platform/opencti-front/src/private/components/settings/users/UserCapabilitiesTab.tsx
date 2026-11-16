import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import EEChip from '@components/common/entreprise_edition/EEChip';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import CapabilitiesList from '../roles/CapabilitiesList';
import { roleEditionCapabilitiesLinesSearch } from '../roles/RoleEditionCapabilities';
import { RoleEditionCapabilitiesLinesSearchQuery } from '../roles/__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { UserCapabilitiesTab_user$data, UserCapabilitiesTab_user$key } from './__generated__/UserCapabilitiesTab_user.graphql';

const userCapabilitiesTabFragment = graphql`
  fragment UserCapabilitiesTab_user on User {
    capabilities {
      name
    }
    capabilitiesInDraft {
      name
    }
  }
`;

/**
 * The two capability cards, like on the Role page. Loads the capability catalogue,
 * which only access managers can read.
 */
const UserCapabilitiesCards = ({
  user,
}: { user: UserCapabilitiesTab_user$data }) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
  );

  return (
    <Grid
      container={true}
      spacing={3}
    >
      <Grid size={6}>
        <Card title={t_i18n('Capabilities')}>
          {queryRef && (
            <React.Suspense>
              <CapabilitiesList
                queryRef={queryRef}
                role={user}
              />
            </React.Suspense>
          )}
        </Card>
      </Grid>
      <Grid size={6}>
        <Card
          title={(
            <>
              {t_i18n('Capabilities in Draft')}
              <EEChip feature={t_i18n('Capabilities in Draft')} />
            </>
          )}
        >
          {queryRef && (
            <React.Suspense>
              <CapabilitiesList
                queryRef={queryRef}
                role={user}
                isCapabilitiesInDraft={true}
              />
            </React.Suspense>
          )}
        </Card>
      </Grid>
    </Grid>
  );
};

/**
 * "Capabilities" tab of a user: every capability the user gets from its roles.
 */
const UserCapabilitiesTab = ({
  data,
}: { data: UserCapabilitiesTab_user$key }) => {
  const user = useFragment(userCapabilitiesTabFragment, data);

  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      <UserCapabilitiesCards user={user} />
    </Security>
  );
};

export default UserCapabilitiesTab;
