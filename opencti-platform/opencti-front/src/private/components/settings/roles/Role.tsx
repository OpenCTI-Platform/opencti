import React from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Link } from 'react-router-dom';
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
import { Grid, ListItemButton, ListItemIcon, ListItemText, Paper, Typography } from '@components';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
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
        <Grid size={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Basic information')}
          </Typography>
          <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid size={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Description')}
                </Typography>
                <ExpandableMarkdown
                  source={role.description}
                  limit={400}
                />
              </Grid>
              <Grid size={12}>
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
          </Paper>
        </Grid>
        <Grid size={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Capabilities')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid size={12} style={{ paddingTop: 10 }}>
                {queryRef && (
                  <React.Suspense>
                    <CapabilitiesList queryRef={queryRef} role={role} />
                  </React.Suspense>
                )}
              </Grid>
            </Grid>
          </Paper>
        </Grid>
      </Grid>
    </div>
  );
};

export default Role;
