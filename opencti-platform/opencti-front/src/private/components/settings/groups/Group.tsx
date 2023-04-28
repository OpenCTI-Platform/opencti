import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import {
  CenterFocusStrongOutlined,
  Edit,
  SecurityOutlined,
} from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import Fab from '@mui/material/Fab';
import Drawer from '@mui/material/Drawer';
import * as R from 'ramda';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import AccessesMenu from '../AccessesMenu';
import { Group_group$key } from './__generated__/Group_group.graphql';
import GroupPopover from './GroupPopover';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import { UserLine } from '../users/UserLine';
import UserLineTitles from '../users/UserLineTitles';
import GroupEdition from './GroupEdition';
import { Theme } from '../../../../components/Theme';
import { truncate } from '../../../../utils/String';

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

const groupFragment = graphql`
  fragment Group_group on Group
  @argumentDefinitions(
      rolesOrderBy: { type: "RolesOrdering", defaultValue: name }
      rolesOrderMode: { type: "OrderingMode", defaultValue: asc }
  ) {
    id
    entity_type
    name
    default_assignation
    auto_new_marking
    description
    members {
      edges {
        node {
          id
          user_email
          name
          firstname
          lastname
          external
        }
      }
    }
    roles(
        orderBy: $rolesOrderBy,
        orderMode: $rolesOrderMode,
    ) {
      id
      name
      description
    }
    allowed_marking {
      id
      definition
      x_opencti_color
      x_opencti_order
    }
    default_marking {
      entity_type
      values {
        id
        definition
        x_opencti_color
        x_opencti_order 
      }
    }
  }
`;

const Group = ({ groupData }: { groupData: Group_group$key }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const group = useFragment<Group_group$key>(groupFragment, groupData);
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
  };
  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };
  const userColumns = {
    name: {
      label: 'Name',
      width: '20%',
      isSortable: true,
    },
    user_email: {
      label: 'Email',
      width: '30%',
      isSortable: true,
    },
    firstname: {
      label: 'Firstname',
      width: '15%',
      isSortable: true,
    },
    lastname: {
      label: 'Lastname',
      width: '15%',
      isSortable: true,
    },
    otp: {
      label: '2FA',
      width: '5%',
      isSortable: false,
    },
    created_at: {
      label: 'Creation date',
      width: '10%',
      isSortable: true,
    },
  };
  const usersSort = R.sortWith([R.ascend(R.pathOr('name', ['node', 'name']))]);
  const members = usersSort(group.members?.edges ?? []);
  const markingsSort = R.sortWith([
    R.ascend(R.propOr('TLP', 'definition_type')),
    R.descend(R.propOr(0, 'x_opencti_order')),
  ]);
  const allowedMarkings = markingsSort(group.allowed_marking ?? []);
  // Handle only GLOBAL entity type for now
  const globalDefaultMarkings = markingsSort((group.default_marking ?? []).find((d) => d.entity_type === 'GLOBAL')?.values ?? []);
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
      >
        {group.name}
      </Typography>
      <div className={classes.popover}>
        <GroupPopover groupId={group.id} />
      </div>
      <div className="clearfix" />
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
                {group.description}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Auto new markings')}
                </Typography>
                <ItemBoolean
                  status={group.auto_new_marking ?? false}
                  label={group.auto_new_marking ? t('Yes') : t('No')}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Default membership')}
                </Typography>
                <ItemBoolean
                  status={group.default_assignation ?? false}
                  label={group.default_assignation ? t('Yes') : t('No')}
                />
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Permissions')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Roles')}
                </Typography>
                <List>
                  {group.roles?.map((role) => (
                    <ListItem
                      key={role?.id}
                      dense={true}
                      divider={true}
                      button={true}
                      component={Link}
                      to={`/dashboard/settings/accesses/roles/${role?.id}`}
                    >
                      <ListItemIcon>
                        <SecurityOutlined color="primary" />
                      </ListItemIcon>
                      <ListItemText primary={role?.name} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Allowed markings')}
                </Typography>
                <List>
                  {allowedMarkings.map((marking) => (
                    <ListItem
                      key={marking?.id}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon
                        style={{ color: marking?.x_opencti_color ?? undefined }}
                      >
                        <CenterFocusStrongOutlined />
                      </ListItemIcon>
                      <ListItemText
                        primary={truncate(marking?.definition, 40)}
                      />
                    </ListItem>
                  ))}
                </List>
                <Typography variant="h3" gutterBottom={true} style={{ paddingTop: 10 }}>
                  {t('Default markings')}
                  <Tooltip title={t('You can enable/disable default values for marking in each specific entity type.')}>
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ margin: '0 0 -5px 10px' }}
                    />
                  </Tooltip>
                </Typography>
                <List>
                  {globalDefaultMarkings.map((marking) => (
                    <ListItem
                      key={marking?.id}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon
                        style={{ color: marking?.x_opencti_color ?? undefined }}
                      >
                        <CenterFocusStrongOutlined />
                      </ListItemIcon>
                      <ListItemText
                        primary={truncate(marking?.definition, 40)}
                      />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 20, marginLeft: 0 }}
        >
          <Grid item={true} xs={12}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Members')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12} style={{ paddingTop: 20 }}>
                  <UserLineTitles dataColumns={userColumns} />
                  <List>
                    {members.map((member) => (
                      <UserLine
                        key={member?.node?.id}
                        dataColumns={userColumns}
                        node={member?.node}
                      />
                    ))}
                  </List>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
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
        <GroupEdition groupId={group.id} handleClose={handleCloseUpdate} />
      </Drawer>
    </div>
  );
};

export default Group;
