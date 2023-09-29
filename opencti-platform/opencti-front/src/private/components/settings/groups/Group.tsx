import { WarningOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { InformationOutline } from 'mdi-material-ui';
import * as R from 'ramda';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import { truncate } from '../../../../utils/String';
import AccessesMenu from '../AccessesMenu';
import Triggers from '../common/Triggers';
import GroupUsers from '../users/GroupUsers';
import { Group_group$key } from './__generated__/Group_group.graphql';
import GroupEdition from './GroupEdition';
import GroupPopover from './GroupPopover';
import ItemIcon from '../../../../components/ItemIcon';
import GroupHiddenTypesChipList from './GroupHiddenTypesChipList';

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
          ...UserLine_node
        }
      }
    }
    default_dashboard {
      id
      name
      authorizedMembers {
        id
      }
    }
    roles(orderBy: $rolesOrderBy, orderMode: $rolesOrderMode) {
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
    ...GroupHiddenTypesChipList_group
  }
`;
const Group = ({ groupData }: { groupData: Group_group$key }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const group = useFragment<Group_group$key>(groupFragment, groupData);
  const markingsSort = R.sortWith([
    R.ascend(R.propOr('TLP', 'definition_type')),
    R.descend(R.propOr(0, 'x_opencti_order')),
  ]);
  const allowedMarkings = markingsSort(group.allowed_marking ?? []);
  // Handle only GLOBAL entity type for now
  const globalDefaultMarkings = markingsSort(
    (group.default_marking ?? []).find((d) => d.entity_type === 'GLOBAL')
      ?.values ?? [],
  );
  const canAccessDashboard = (
    group.default_dashboard?.authorizedMembers || []
  ).some(({ id }) => ['ALL', group.id].includes(id));
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
              <Grid item={true} xs={12}>
                <GroupHiddenTypesChipList groupData={group} />
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
                        <ItemIcon type="Role" />
                      </ListItemIcon>
                      <ListItemText primary={role?.name} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Default dashboard')}
                </Typography>
                <FieldOrEmpty source={group.default_dashboard}>
                  <List>
                    <ListItem
                      dense={true}
                      divider={true}
                      button={true}
                      component={Link}
                      to={`/dashboard/workspaces/dashboards/${group.default_dashboard?.id}`}
                    >
                      <ListItemIcon>
                        <ItemIcon type="Dashboard" />
                      </ListItemIcon>
                      <ListItemText
                        primary={truncate(group.default_dashboard?.name, 40)}
                      />
                      {!canAccessDashboard && (
                        <ListItemSecondaryAction>
                          <Tooltip
                            title={t(
                              'You need to authorize this group to access this dashboard in the permissions of the workspace.',
                            )}
                          >
                            <WarningOutlined color="warning" />
                          </Tooltip>
                        </ListItemSecondaryAction>
                      )}
                    </ListItem>
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Default markings')}
                  <Tooltip
                    title={t(
                      'You can enable/disable default values for marking in the customization of each entity type.',
                    )}
                  >
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ margin: '0 0 -5px 10px' }}
                    />
                  </Tooltip>
                </Typography>
                <FieldOrEmpty source={globalDefaultMarkings}>
                  <List style={{ marginTop: -3 }}>
                    {globalDefaultMarkings.map((marking) => (
                      <ListItem
                        key={marking?.id}
                        dense={true}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon>
                          <ItemIcon
                            type="Marking-Definition"
                            color={marking?.x_opencti_color ?? undefined}
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={truncate(marking?.definition, 40)}
                        />
                      </ListItem>
                    ))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Allowed markings')}
                </Typography>
                <FieldOrEmpty source={allowedMarkings}>
                  <List>
                    {allowedMarkings.map((marking) => (
                      <ListItem
                        key={marking?.id}
                        dense={true}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon>
                          <ItemIcon
                            type="Marking-Definition"
                            color={marking?.x_opencti_color ?? undefined}
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={truncate(marking?.definition, 40)}
                        />
                      </ListItem>
                    ))}
                  </List>
                </FieldOrEmpty>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 10, marginLeft: 0 }}
        >
          <Triggers recipientId={group.id} filter="group_ids" />
          <GroupUsers groupId={group.id} />
        </Grid>
      </Grid>
      <GroupEdition groupId={group.id}/>
    </div>
  );
};

export default Group;
