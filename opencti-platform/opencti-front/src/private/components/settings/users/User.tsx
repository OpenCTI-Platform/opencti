import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { AccountBalanceOutlined, Delete, DeleteForeverOutlined, Edit, GroupOutlined, ReceiptOutlined, SecurityOutlined } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { interval } from 'rxjs';
import { Link } from 'react-router-dom';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { ApexOptions } from 'apexcharts';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import UserEdition from './UserEdition';
import UserPopover, { userEditionQuery } from './UserPopover';
import { handleError, QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FIVE_SECONDS, now, timestamp, yearsAgo } from '../../../../utils/Time';
import UserHistory from './UserHistory';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import Transition from '../../../../components/Transition';
import { User_user$key } from './__generated__/User_user.graphql';
import { Theme } from '../../../../components/Theme';
import AccessesMenu from '../AccessesMenu';
import Chart from '../../common/charts/Chart';
import { UserSessionKillMutation } from './__generated__/UserSessionKillMutation.graphql';
import { UserUserSessionsKillMutation } from './__generated__/UserUserSessionsKillMutation.graphql';
import Triggers from '../common/Triggers';
import { UserLogsTimeSeriesQuery$data } from './__generated__/UserLogsTimeSeriesQuery.graphql';
import { UserPopoverEditionQuery$data } from './__generated__/UserPopoverEditionQuery.graphql';
import { UserOtpDeactivationMutation } from './__generated__/UserOtpDeactivationMutation.graphql';

Transition.displayName = 'TransitionSlide';

const interval$ = interval(FIVE_SECONDS);
const startDate = yearsAgo(1);
const endDate = now();

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  floatingButton: {
    float: 'left',
    margin: '-8px 0 0 5px',
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
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

export const userSessionKillMutation = graphql`
  mutation UserSessionKillMutation($id: ID!) {
    sessionKill(id: $id)
  }
`;

export const userUserSessionsKillMutation = graphql`
  mutation UserUserSessionsKillMutation($id: ID!) {
    userSessionsKill(id: $id)
  }
`;

export const userOtpDeactivationMutation = graphql`
  mutation UserOtpDeactivationMutation($id: ID!) {
    otpUserDeactivation(id: $id) {
      ...ProfileOverview_me
    }
  }
`;

const userLogsTimeSeriesQuery = graphql`
  query UserLogsTimeSeriesQuery(
    $field: String!
    $userId: String
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    logsTimeSeries(
      field: $field
      userId: $userId
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

const userFragment = graphql`
  fragment User_user on User
  @argumentDefinitions(
    rolesOrderBy: { type: "RolesOrdering", defaultValue: name }
    rolesOrderMode: { type: "OrderingMode", defaultValue: asc }
    groupsOrderBy: { type: "GroupsOrdering", defaultValue: name }
    groupsOrderMode: { type: "OrderingMode", defaultValue: asc }
    organizationsOrderBy: { type: "OrganizationsOrdering", defaultValue: name }
    organizationsOrderMode: { type: "OrderingMode", defaultValue: asc }
  ) {
    id
    name
    description
    external
    user_email
    firstname
    lastname
    language
    api_token
    otp_activated
    roles(orderBy: $rolesOrderBy, orderMode: $rolesOrderMode) {
      id
      name
      description
    }
    capabilities {
      id
      name
    }
    groups(orderBy: $groupsOrderBy, orderMode: $groupsOrderMode) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
    default_hidden_types
    objectOrganization(
      orderBy: $organizationsOrderBy
      orderMode: $organizationsOrderMode
    ) {
      edges {
        node {
          id
          name
        }
      }
    }
    sessions {
      id
      created
      ttl
    }
  }
`;

type Session = {
  id: string;
  created?: string;
  ttl?: number;
};

interface UserProps {
  userData: User_user$key;
  refetch: () => void;
}

const User: FunctionComponent<UserProps> = ({ userData, refetch }) => {
  const classes = useStyles();
  const { t, nsdt, fsd } = useFormatter();
  const theme = useTheme();
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const [displayKillSession, setDisplayKillSession] = useState<boolean>(false);
  const [displayKillSessions, setDisplayKillSessions] = useState<boolean>(false);
  const [killing, setKilling] = useState<boolean>(false);
  const [sessionToKill, setSessionToKill] = useState<string | null>(null);

  const user = useFragment(userFragment, userData);

  const [commitUserSessionKill] = useMutation<UserSessionKillMutation>(
    userSessionKillMutation,
  );
  const [commitUserUserSessionsKill] = useMutation<UserUserSessionsKillMutation>(userUserSessionsKillMutation);
  const [commitUserOtpDeactivation] = useMutation<UserOtpDeactivationMutation>(
    userOtpDeactivationMutation,
  );

  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
  };

  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };

  const handleOpenKillSession = (sessionId: string) => {
    setDisplayKillSession(true);
    setSessionToKill(sessionId);
  };

  const handleCloseKillSession = () => {
    setDisplayKillSession(false);
    setSessionToKill(null);
  };

  const submitKillSession = () => {
    if (sessionToKill) {
      setKilling(true);
      commitUserSessionKill({
        variables: {
          id: sessionToKill,
        },
        onError: (error: Error) => {
          handleError(error);
          setKilling(false);
        },
        onCompleted: () => {
          setKilling(false);
          handleCloseKillSession();
        },
      });
    }
  };

  const handleOpenKillSessions = () => {
    setDisplayKillSessions(true);
  };

  const handleCloseKillSessions = () => {
    setDisplayKillSessions(false);
  };

  const submitKillSessions = () => {
    setKilling(true);
    commitUserUserSessionsKill({
      variables: {
        id: user.id,
      },
      onError: (error: Error) => {
        handleError(error);
        setKilling(false);
      },
      onCompleted: () => {
        setKilling(false);
        handleCloseKillSessions();
      },
    });
  };

  const otpUserDeactivation = () => {
    commitUserOtpDeactivation({
      variables: {
        id: user.id,
      },
      onError: (error: Error) => {
        handleError(error);
      },
    });
  };

  const orderedSessions: Session[] = (user.sessions ?? [])
    .map((s) => ({
      created: s?.created ?? '',
      id: s?.id ?? '',
      ttl: s?.ttl ?? 0,
    }))
    .sort(
      (a: Session, b: Session) => timestamp(a?.created) - timestamp(b?.created),
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
          {user.name}
        </Typography>
        <div className={classes.popover}>
          <UserPopover userId={user.id} />
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
              <Grid item={true} xs={8}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ marginBottom: 7 }}
                >
                  {t('Email address')}
                </Typography>
                <pre style={{ margin: 0 }}>{user.user_email}</pre>
              </Grid>
              <Grid item={true} xs={4}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('2FA state')}
                </Typography>
                {user.otp_activated && (
                  <IconButton
                    classes={{ root: classes.floatingButton }}
                    color="secondary"
                    onClick={otpUserDeactivation}
                    aria-label="Delete all"
                    size="small"
                  >
                    <DeleteForeverOutlined fontSize="small" />
                  </IconButton>
                )}
                <div className="clearfix" />
                <pre style={{ margin: 0 }}>
                  {user.otp_activated ? t('Enabled') : t('Disabled')}
                </pre>
              </Grid>
              <Grid item={true} xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Token')}
                </Typography>
                <pre style={{ margin: 0 }}>{user.api_token}</pre>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Firstname')}
                </Typography>
                {user.firstname || '-'}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Lastname')}
                </Typography>
                {user.lastname || '-'}
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
                  {(user.roles ?? []).map((role) => (
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
                  {t('Groups')}
                </Typography>
                <FieldOrEmpty source={user.groups?.edges}>
                  <List>
                    {(user.groups?.edges ?? []).map((groupEdge) => (
                      <ListItem
                        key={groupEdge?.node.id}
                        dense={true}
                        divider={true}
                        button={true}
                        component={Link}
                        to={`/dashboard/settings/accesses/groups/${groupEdge?.node.id}`}
                      >
                        <ListItemIcon>
                          <GroupOutlined color="primary" />
                        </ListItemIcon>
                        <ListItemText primary={groupEdge?.node.name} />
                      </ListItem>
                    ))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item={true} xs={6} style={{ marginTop: 30 }}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Organizations')}
                </Typography>
                <FieldOrEmpty source={user.objectOrganization?.edges}>
                  <List>
                    {user.objectOrganization?.edges.map((organizationEdge) => (
                      <ListItem
                        key={organizationEdge.node.id}
                        dense={true}
                        divider={true}
                        button={true}
                        component={Link}
                        to={`/dashboard/settings/accesses/organizations/${organizationEdge.node.id}`}
                      >
                        <ListItemIcon>
                          <AccountBalanceOutlined color="primary" />
                        </ListItemIcon>
                        <ListItemText primary={organizationEdge.node.name} />
                      </ListItem>
                    ))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Sessions')}
                </Typography>
                <IconButton
                  color="secondary"
                  aria-label="Delete all"
                  onClick={handleOpenKillSessions}
                  classes={{ root: classes.floatingButton }}
                  size="small"
                >
                  <DeleteForeverOutlined fontSize="small" />
                </IconButton>
                <div className="clearfix" />
                <List>
                  {orderedSessions
                    && orderedSessions.map((session: Session) => (
                      <ListItem
                        key={session.id}
                        dense={true}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon>
                          <ReceiptOutlined color="primary" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <div>
                              <div style={{ float: 'left', width: '50%' }}>
                                {nsdt(session.created)}
                              </div>
                              <div style={{ float: 'left', width: '20%' }}>
                                {session.ttl ? Math.round(session.ttl / 60) : 0}{' '}
                                {t('minutes')}
                              </div>
                            </div>
                          }
                        />
                        <ListItemSecondaryAction>
                          <IconButton
                            aria-label="Kill"
                            onClick={() => handleOpenKillSession(session.id)}
                            size="large"
                          >
                            <Delete fontSize="small" />
                          </IconButton>
                        </ListItemSecondaryAction>
                      </ListItem>
                    ))}
                </List>
              </Grid>
              <Grid item={true} xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Hidden entity types')}
                </Typography>
                <FieldOrEmpty source={user.default_hidden_types}>
                  {user.default_hidden_types.map((name) => (
                    <Chip
                      key={name}
                      classes={{ root: classes.chip }}
                      label={name}
                    />
                  ))}
                </FieldOrEmpty>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Triggers recipientId={user.id} filter="user_ids" />
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Operations')}
          </Typography>
          <Paper
            classes={{ root: classes.paper }}
            variant="outlined"
            style={{ marginTop: 15 }}
          >
            <QueryRenderer
              query={userLogsTimeSeriesQuery}
              variables={{
                field: 'timestamp',
                operation: 'count',
                startDate,
                endDate,
                interval: 'month',
                userId: user.id,
              }}
              render={({ props }: { props: UserLogsTimeSeriesQuery$data }) => {
                if (props && props.logsTimeSeries) {
                  const chartData = props.logsTimeSeries.map((entry) => ({
                    x: new Date(entry?.date),
                    y: entry?.value,
                  }));
                  return (
                    <Chart
                      options={
                        areaChartOptions(
                          theme,
                          true,
                          fsd,
                          simpleNumberFormat,
                          undefined,
                        ) as ApexOptions
                      }
                      series={[
                        {
                          name: t('Number of operations'),
                          data: chartData,
                        },
                      ]}
                      type="area"
                      width="100%"
                      height="100%"
                    />
                  );
                }
                return <Loader variant={LoaderVariant.inElement} />;
              }}
            />
          </Paper>
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <UserHistory userId={user.id} />
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
          query={userEditionQuery}
          variables={{ id: user.id }}
          render={({ props }: { props: UserPopoverEditionQuery$data }) => {
            if (props && props.user) {
              return (
                <UserEdition
                  user={props.user}
                  handleClose={handleCloseUpdate}
                />
              );
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </Drawer>
      <Dialog
        open={displayKillSession}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseKillSession}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to kill this session?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseKillSession}
            color="primary"
            disabled={killing}
          >
            {t('Cancel')}
          </Button>
          <Button
            onClick={submitKillSession}
            color="primary"
            disabled={killing}
          >
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayKillSessions}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseKillSessions}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to kill all the sessions of this user?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseKillSessions}
            color="primary"
            disabled={killing}
          >
            {t('Cancel')}
          </Button>
          <Button
            onClick={submitKillSessions}
            color="primary"
            disabled={killing}
          >
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export const userQuery = graphql`
  query UserQuery(
    $id: String!
    $rolesOrderBy: RolesOrdering
    $rolesOrderMode: OrderingMode
    $groupsOrderBy: GroupsOrdering
    $groupsOrderMode: OrderingMode
    $organizationsOrderBy: OrganizationsOrdering
    $organizationsOrderMode: OrderingMode
  ) {
    user(id: $id) {
      id
      name
      ...User_user
      @arguments(
        rolesOrderBy: $rolesOrderBy
        rolesOrderMode: $rolesOrderMode
        groupsOrderBy: $groupsOrderBy
        groupsOrderMode: $groupsOrderMode
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
    }
  }
`;

export default User;
