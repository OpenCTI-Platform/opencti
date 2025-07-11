import React, { useState } from 'react';
import { graphql, PreloadedQuery, useFragment, useLazyLoadQuery, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { Link, useNavigate, useParams } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Box, ListItemButton, styled } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import { roleDeletionMutation } from '@components/settings/roles/RoleEditionOverview';
import { useTheme } from '@mui/styles';
import AccessesMenu from '../AccessesMenu';
import { useFormatter } from '../../../../components/i18n';
import { Role_role$data, Role_role$key } from './__generated__/Role_role.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import RoleEdition from './RoleEdition';
import { RoleEditionQuery } from './__generated__/RoleEditionQuery.graphql';
import CapabilitiesList from './CapabilitiesList';
import { groupsSearchQuery } from '../Groups';
import { GroupsSearchQuery } from '../__generated__/GroupsSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import type { Theme } from '../../../../components/Theme';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import PopoverMenu from '../../../../components/PopoverMenu';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';

const roleEditionQuery = graphql`
  query RoleEditionQuery($id: String!) {
    role(id: $id) {
      ...RoleEdition_role
    }
  }
`;

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
  const navigate = useNavigate();
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const theme = useTheme<Theme>();
  const { roleId } = useParams() as { roleId: string };
  const [openDelete, setOpenDelete] = useState(false);

  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('Role') },
  });
  const deletion = useDeletion({});
  const { setDeleting } = deletion;
  const [commit] = useApiMutation(
    roleDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id: roleId },
      onCompleted: () => {
        setDeleting(false);
        navigate('/dashboard/settings/accesses/roles');
      },
    });
  };

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
  const roleEditionData = useLazyLoadQuery<RoleEditionQuery>(
    roleEditionQuery,
    { id: role.id },
  );

  const RoleHeader = styled('div')({
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: 24,
  });

  return (
    <div className={classes.container}>
      <AccessesMenu/>
      <RoleHeader>
        <div>
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
          >
            {role.name}
          </Typography>
          <div className="clearfix" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <div style={{ display: 'flex' }}>
            <div style={{ marginRight: theme.spacing(0.5) }}>
              {canDelete && (
              <PopoverMenu>
                {({ closeMenu }) => (
                  <Box>
                    <MenuItem onClick={() => {
                      handleOpenDelete();
                      closeMenu();
                    }}
                    >
                      {t_i18n('Delete')}
                    </MenuItem>
                  </Box>
                )}
              </PopoverMenu>
              )}
            </div>
            <DeleteDialog
              deletion={deletion}
              isOpen={openDelete}
              onClose={handleCloseDelete}
              submitDelete={submitDelete}
              message={t_i18n('Do you want to delete this role?')}
            />
            <RoleEdition
              roleEditionData={roleEditionData}
              disabled={!isAllowed && isSensitive}
            />
          </div>
        </div>
      </RoleHeader>
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
