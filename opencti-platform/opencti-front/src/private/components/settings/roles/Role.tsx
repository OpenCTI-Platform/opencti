import React, { useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Chip from '@mui/material/Chip';
import Fab from '@mui/material/Fab';
import { Edit, GroupOutlined } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
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
import {
  RoleEditionCapabilitiesLinesSearchQuery,
} from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { Theme } from '../../../../components/Theme';
import { QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import RoleEdition from './RoleEdition';
import { RolePopoverEditionQuery$data } from './__generated__/RolePopoverEditionQuery.graphql';
import CapabilitiesList from './CapabilitiesList';
import { groupsSearchQuery } from '../Groups';
import { GroupsSearchQuery } from '../__generated__/GroupsSearchQuery.graphql';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';
import { isEmptyField } from '../../../../utils/utils';

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
    textTransform: 'uppercase',
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
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 5,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
  grey_chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.grey?.[700],
    borderRadius: 5,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
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
        default_hidden_types
    }
`;

const Role = ({ roleData, groupsQueryRef }: {
  roleData: Role_role$key,
  groupsQueryRef: PreloadedQuery<GroupsSearchQuery>
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const history = useHistory();
  const groupsData = usePreloadedQuery(groupsSearchQuery, groupsQueryRef);
  const groupNodes = (role: Role_role$data) => {
    return (groupsData.groups?.edges ?? [])
      .map((group) => ((((group?.node.roles ?? [])
        .map((r) => r?.id)).includes(role.id)) ? group?.node : null))
      .filter((n) => n !== null && n !== undefined);
  };

  const hiddenTypes = useEntitySettings()
    .filter((entitySetting) => entitySetting.platform_hidden_type === true)
    .map((hiddenType) => hiddenType.target_type);

  const role = useFragment<Role_role$key>(roleFragment, roleData);
  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(roleEditionCapabilitiesLinesSearch);

  const [displayUpdate, setDisplayUpdate] = useState(false);

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
  };

  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };

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
                  {t('Hidden entity types')}
                </Typography>
                {hiddenTypes.map((name) => (!role.default_hidden_types?.includes(name)
                  ? <Chip
                  key={name}
                  classes={{ root: classes.grey_chip }}
                  label={t(`entity_${name}`)}
                />
                  : <></>))}
                {role.default_hidden_types && role.default_hidden_types.map((name) => <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={t(`entity_${name}`)}
                />)}
                {isEmptyField(hiddenTypes) && isEmptyField(role.default_hidden_types) && <div>{'-'}</div>}
              </Grid>
              <Grid item={true} xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Groups with this role')}
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
                        <GroupOutlined color="primary" />
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
                {queryRef
                  && <React.Suspense>
                    <CapabilitiesList queryRef={queryRef} role={role} ></CapabilitiesList>
                  </React.Suspense>
                }
              </Grid>
            </Grid>
          </Paper>
        </Grid>
      </Grid>
      <Fab
        onClick={handleOpenUpdate}
        color="secondary"
        aria-label="Edit"
        className={classes.editButton}
      >
        <Edit />
      </Fab>
      <Drawer
        open={displayUpdate}
        anchor="right"
        sx={{ zIndex: 1202 }}
        elevation={1}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseUpdate}
      >
        <QueryRenderer
          query={roleEditionQuery}
          variables={{ id: role.id }}
          render={({ props }: { props: RolePopoverEditionQuery$data }) => {
            if (props && props.role) {
              return (
                <RoleEdition
                  role={props.role}
                  handleClose={handleCloseUpdate}
                />
              );
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </Drawer>
    </div>
  );
};

export default Role;
