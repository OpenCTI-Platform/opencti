import React from 'react';
import { graphql, PreloadedQuery, useFragment, useLazyLoadQuery, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import AccessesMenu from '../AccessesMenu';
import { useFormatter } from '../../../../components/i18n';
import { Role_role$data, Role_role$key } from './__generated__/Role_role.graphql';
import RolePopover, { roleEditionQuery } from './RolePopover';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import RoleEdition from './RoleEdition';
import { RolePopoverEditionQuery } from './__generated__/RolePopoverEditionQuery.graphql';
import CapabilitiesList from './CapabilitiesList';
import { groupsSearchQuery } from '../Groups';
import { GroupsSearchQuery } from '../__generated__/GroupsSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import type { Theme } from '../../../../components/Theme';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import useHelper from '../../../../utils/hooks/useHelper';

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
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
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
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
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
  const { isAllowed, isSensitive } = useSensitiveModifications('roles', role.standard_id);
  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
  );
  const roleEditionData = useLazyLoadQuery<RolePopoverEditionQuery>(
    roleEditionQuery,
    { id: role.id },
  );
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {role.name}
        </Typography>
        {!isFABReplaced && <div className={classes.popover}>
          <RolePopover
            roleId={role.id}
            disabled={!isAllowed && isSensitive}
            isSensitive={isSensitive}
            roleEditionData={roleEditionData}
          />
        </div>}
        <RoleEdition
          roleEditionData={roleEditionData}
          disabled={!isAllowed && isSensitive}
        />
        <div className="clearfix"/>
      </div>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Basic information')}
          </Typography>
          <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
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
                    <ListItem
                      key={group?.id}
                      dense={true}
                      divider={true}
                      button={true}
                      component={Link}
                      to={`/dashboard/settings/accesses/groups/${group?.id}`}
                    >
                      <ListItemIcon>
                        <ItemIcon type="Group" />
                      </ListItemIcon>
                      <ListItemText primary={group?.name} />
                    </ListItem>
                  ))}
                </div>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Capabilities')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid item xs={12} style={{ paddingTop: 10 }}>
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
