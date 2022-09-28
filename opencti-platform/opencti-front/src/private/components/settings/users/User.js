import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import {
  Edit,
  GroupOutlined,
  Delete,
  DeleteForeverOutlined,
  SecurityOutlined,
  ReceiptOutlined,
} from '@mui/icons-material';
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
import Slide from '@mui/material/Slide';
import { interval } from 'rxjs';
import * as R from 'ramda';
import Chart from 'react-apexcharts';
import inject18n from '../../../../components/i18n';
import UserEdition from './UserEdition';
import UserPopover, { userEditionQuery } from './UserPopover';
import AccessesMenu from '../AccessesMenu';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import { FIVE_SECONDS, now, timestamp, yearsAgo } from '../../../../utils/Time';
import UserHistory from './UserHistory';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const interval$ = interval(FIVE_SECONDS);
const startDate = yearsAgo(1);
const endDate = now();

const styles = (theme) => ({
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
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  graphContainer: {
    width: '100%',
    padding: '20px 20px 0 0',
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: '0',
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
});

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

class UserComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayUpdate: false,
      displayKillSession: false,
      killing: false,
      sessionToKill: null,
    };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch({ id: this.props.user.id });
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
  }

  handleCloseUpdate() {
    this.setState({ displayUpdate: false });
  }

  handleOpenKillSession(session) {
    this.setState({ displayKillSession: true, sessionToKill: session });
  }

  handleCloseKillSession() {
    this.setState({ displayKillSession: false, sessionToKill: null });
  }

  submitKillSession() {
    this.setState({ killing: true });
    commitMutation({
      mutation: userSessionKillMutation,
      variables: {
        id: this.state.sessionToKill,
      },
      onCompleted: () => {
        this.setState({ killing: false });
        this.handleCloseKillSession();
      },
    });
  }

  handleOpenKillSessions() {
    this.setState({ displayKillSessions: true });
  }

  handleCloseKillSessions() {
    this.setState({ displayKillSessions: false });
  }

  submitKillSessions() {
    this.setState({ killing: true });
    commitMutation({
      mutation: userUserSessionsKillMutation,
      variables: {
        id: this.props.user.id,
      },
      onCompleted: () => {
        this.setState({ killing: false });
        this.handleCloseKillSessions();
      },
    });
  }

  otpUserDeactivation() {
    commitMutation({
      mutation: userOtpDeactivationMutation,
      variables: {
        id: this.props.user.id,
      },
    });
  }

  render() {
    const { classes, theme, user, t, fsd, nsdt } = this.props;
    const orderedSessions = R.sort(
      (a, b) => timestamp(a.created) - timestamp(b.created),
      user.sessions,
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
                      onClick={this.otpUserDeactivation.bind(this)}
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
                    {user.roles.map((role) => (
                      <ListItem
                        key={role.id}
                        dense={true}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon>
                          <SecurityOutlined color="primary" />
                        </ListItemIcon>
                        <ListItemText primary={role.name} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Groups')}
                  </Typography>
                  <List>
                    {user.groups.edges.map((groupEdge) => (
                      <ListItem
                        key={groupEdge.node.id}
                        dense={true}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon>
                          <GroupOutlined color="primary" />
                        </ListItemIcon>
                        <ListItemText primary={groupEdge.node.name} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item={true} xs={12}>
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
                    onClick={this.handleOpenKillSessions.bind(this)}
                    classes={{ root: classes.floatingButton }}
                    size="small"
                  >
                    <DeleteForeverOutlined fontSize="small" />
                  </IconButton>
                  <div className="clearfix" />
                  <List>
                    {orderedSessions.map((session) => (
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
                                {Math.round(session.ttl / 60)} {t('minutes')}
                              </div>
                            </div>
                          }
                        />
                        <ListItemSecondaryAction>
                          <IconButton
                            aria-label="Kill"
                            onClick={this.handleOpenKillSession.bind(
                              this,
                              session.id,
                            )}
                            size="large"
                          >
                            <Delete fontSize="small" />
                          </IconButton>
                        </ListItemSecondaryAction>
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 20 }}
        >
          <Grid item={true} xs={12}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Operations')}
            </Typography>
            <Paper
              classes={{ root: classes.paper }}
              variant="outlined"
              style={{ height: 300 }}
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
                render={({ props }) => {
                  if (props && props.logsTimeSeries) {
                    const chartData = props.logsTimeSeries.map((entry) => ({
                      x: new Date(entry.date),
                      y: entry.value,
                    }));
                    return (
                      <Chart
                        options={areaChartOptions(
                          theme,
                          true,
                          fsd,
                          simpleNumberFormat,
                          undefined,
                        )}
                        series={[
                          {
                            name: t('Number of relationships'),
                            data: chartData,
                          },
                        ]}
                        type="area"
                        width="100%"
                        height="100%"
                      />
                    );
                  }
                  return <Loader variant="inElement" />;
                }}
              />
            </Paper>
          </Grid>
        </Grid>
        <UserHistory userId={user.id} />
        <Fab
          onClick={this.handleOpenUpdate.bind(this)}
          color="secondary"
          aria-label="Edit"
          className={classes.editButton}
        >
          <Edit />
        </Fab>
        <Drawer
          open={this.state.displayUpdate}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseUpdate.bind(this)}
        >
          <QueryRenderer
            query={userEditionQuery}
            variables={{ id: user.id }}
            render={({ props }) => {
              if (props) {
                return (
                  <UserEdition
                    user={props.user}
                    handleClose={this.handleCloseUpdate.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer>
        <Dialog
          open={this.state.displayKillSession}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseKillSession.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to kill this session?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseKillSession.bind(this)}
              color="primary"
              disabled={this.state.killing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitKillSession.bind(this)}
              color="primary"
              disabled={this.state.killing}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          open={this.state.displayKillSessions}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseKillSessions.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to kill all the sessions of this user?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseKillSessions.bind(this)}
              color="primary"
              disabled={this.state.killing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitKillSessions.bind(this)}
              color="primary"
              disabled={this.state.killing}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

UserComponent.propTypes = {
  user: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export const userQuery = graphql`
  query UserQuery($id: String!) {
    user(id: $id) {
      id
      name
      ...User_user
    }
  }
`;

const User = createRefetchContainer(
  UserComponent,
  {
    user: graphql`
      fragment User_user on User {
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
        roles {
          id
          name
          description
        }
        groups {
          edges {
            node {
              id
              name
              description
            }
          }
        }
        sessions {
          id
          created
          ttl
        }
      }
    `,
  },
  userQuery,
);

export default compose(inject18n, withTheme, withStyles(styles))(User);
