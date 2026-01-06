import React from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../../components/i18n';
import { Role_role$data, Role_role$key } from './__generated__/Role_role.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import CapabilitiesList from './CapabilitiesList';
import { groupsSearchQuery } from '../Groups';
import { GroupsSearchQuery } from '../__generated__/GroupsSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import type { Theme } from '../../../../components/Theme';
import useHelper from '../../../../utils/hooks/useHelper';
import Card from '../../../../components/common/card/Card';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const roleFragment = graphql`
  fragment Role_role on Role {
    id
    standard_id
    name
    description
    created_at
    updated_at
    capabilities {
      id
      name
      description
    }
    capabilitiesInDraft {
      id
      name
      description
    }
    can_manage_sensitive_config
  }
`;

const Role = ({
  roleData,
  groupsQueryRef,
}: {
  roleData: Role_role$key;
  groupsQueryRef: PreloadedQuery<GroupsSearchQuery>;
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isCapabilitiesInDraftEnabled = isFeatureEnable('CAPABILITIES_IN_DRAFT');

  const groupsData = usePreloadedQuery(groupsSearchQuery, groupsQueryRef);
  const groupNodes = (role: Role_role$data) => {
    return (groupsData.groups?.edges ?? [])
      .map((group) => ((group?.node.roles?.edges ?? []).map(({ node: r }) => r?.id).includes(role.id)
        ? group?.node
        : null))
      .filter((n) => n !== null && n !== undefined);
  };
  const role = useFragment<Role_role$key>(roleFragment, roleData);
  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
  );

  return (
    <div className={classes.container} data-testid="role-details-page">
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={12}>
          <Card title={t_i18n('Basic information')}>
            <Grid container={true} spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Description')}
                </Typography>
                <ExpandableMarkdown
                  source={role.description}
                  limit={400}
                />
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Groups using this role')}
                </Typography>
                <div>
                  {groupNodes(role)?.map((group) => (
                    <ListItemButton
                      key={group?.id}
                      dense={true}
                      divider={true}
                      component={Link}
                      to={`/dashboard/settings/accesses/groups/${group?.id}`}
                    >
                      <ListItemIcon>
                        <ItemIcon type="Group" />
                      </ListItemIcon>
                      <ListItemText primary={group?.name} />
                    </ListItemButton>
                  ))}
                </div>
              </Grid>
            </Grid>
          </Card>
        </Grid>
        <Grid container={true} item xs={12} spacing={3}>
          <Grid item xs={6}>
            <Card title={t_i18n('Capabilities')}>
              <Grid container={true} spacing={3}>
                <Grid item xs={12} style={{ paddingTop: 10 }}>
                  {queryRef && (
                    <React.Suspense>
                      <CapabilitiesList queryRef={queryRef} role={role} />
                    </React.Suspense>
                  )}
                </Grid>
              </Grid>
            </Card>
          </Grid>
          {isCapabilitiesInDraftEnabled && (
            <Grid item xs={6}>
              <Card title={(
                <>
                  {t_i18n('Capabilities in Draft')}
                  <EEChip feature={t_i18n('Capabilities in Draft')} />
                </>
              )}
              >
                <Grid container={true} spacing={3}>
                  <Grid item xs={12} style={{ paddingTop: 10 }}>
                    {queryRef && (
                      <React.Suspense>
                        <CapabilitiesList queryRef={queryRef} role={role} isCapabilitiesInDraft />
                      </React.Suspense>
                    )}
                  </Grid>
                </Grid>
              </Card>
            </Grid>
          )}
        </Grid>
      </Grid>
    </div>
  );
};

export default Role;
