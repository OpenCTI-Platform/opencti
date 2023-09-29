import React from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import ListItem from '@mui/material/ListItem';
import { Link, useHistory } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import AccessesMenu from '../AccessesMenu';
import { useFormatter } from '../../../../components/i18n';
import { Role_role$data, Role_role$key } from './__generated__/Role_role.graphql';
import RolePopover, { roleEditionQuery } from './RolePopover';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import RoleEdition from './RoleEdition';
import { RolePopoverEditionQuery$data } from './__generated__/RolePopoverEditionQuery.graphql';
import CapabilitiesList from './CapabilitiesList';
import { groupsSearchQuery } from '../Groups';
import { GroupsSearchQuery } from '../__generated__/GroupsSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';

const useStyles = makeStyles(() => ({
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
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

const roleFragment = graphql`
  fragment Role_role on Role {
    id
    name
    description
    created_at
    updated_at
    capabilities {
      id
      name
      description
    }
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
  const { t } = useFormatter();
  const history = useHistory();
  const groupsData = usePreloadedQuery(groupsSearchQuery, groupsQueryRef);
  const groupNodes = (role: Role_role$data) => {
    return (groupsData.groups?.edges ?? [])
      .map((group) => ((group?.node.roles ?? []).map((r) => r?.id).includes(role.id)
        ? group?.node
        : null))
      .filter((n) => n !== null && n !== undefined);
  };
  const role = useFragment<Role_role$key>(roleFragment, roleData);
  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
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
        <div className={classes.popover}>
          <RolePopover history={history} roleId={role.id} />
        </div>
        <div className="clearfix" />
      </div>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Basic information')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Description')}
                </Typography>
                {role.description}
              </Grid>
              <Grid item={true} xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Groups using this role')}
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
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Capabilities')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={12} style={{ paddingTop: 10 }}>
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
      <QueryRenderer
        query={roleEditionQuery}
        variables={{ id: role.id }}
        render={({ props }: { props: RolePopoverEditionQuery$data }) => {
          if (props && props.role) {
            return (
              <RoleEdition
                role={props.role}
              />
            );
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    </div>
  );
};

export default Role;
