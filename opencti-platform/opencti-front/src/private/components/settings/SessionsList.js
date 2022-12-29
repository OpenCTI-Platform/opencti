import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link, withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { ReceiptOutlined, PersonOutlined, Delete } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import { interval } from 'rxjs';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { graphql, createRefetchContainer } from 'react-relay';
import inject18n from '../../../components/i18n';
import { commitMutation } from '../../../relay/environment';
import { FIVE_SECONDS, timestamp } from '../../../utils/Time';
import { userSessionKillMutation } from './users/User';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  item: {},
  itemNested: {
    paddingLeft: theme.spacing(4),
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  name: {
    width: '20%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  email: {
    width: '70%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    color: '#a5a5a5',
    fontSize: 12,
  },
  created: {
    width: '50%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  ttl: {
    width: '40%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    color: '#a5a5a5',
    fontSize: 12,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
});

class SessionsListComponent extends Component {
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
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
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

  render() {
    const { classes, nsdt, t, data, keyword } = this.props;
    const sortByNameCaseInsensitive = R.sortBy(
      R.compose(R.toLower, R.path(['user', 'name'])),
    );
    const filterByKeyword = (n) => keyword === ''
      || n.user.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || n.user.user_email.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    const sessions = R.pipe(
      R.propOr([], 'sessions'),
      R.filter(filterByKeyword),
      sortByNameCaseInsensitive,
    )(data);
    return (
      <div>
        <List
          component="nav"
          aria-labelledby="nested-list-subheader"
          className={classes.root}
        >
          {sessions.map((session) => {
            const { user, sessions: userSessions } = session;
            const orderedSessions = R.sort(
              (a, b) => timestamp(a.created) - timestamp(b.created),
              userSessions,
            );
            return (
              <div key={session.user.id}>
                <ListItem
                  classes={{ root: classes.item }}
                  divider={true}
                  button={true}
                  component={Link}
                  to={`/dashboard/settings/accesses/users/${user.id}`}
                >
                  <ListItemIcon classes={{ root: classes.itemIcon }}>
                    <PersonOutlined fontSize="medium" />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <div>
                        <div className={classes.name}>{user.name}</div>
                        <div className={classes.email}>{user.email}</div>
                      </div>
                    }
                  />
                  <ListItemIcon classes={{ root: classes.goIcon }}>
                    &nbsp;
                  </ListItemIcon>
                </ListItem>
                <List style={{ margin: 0, padding: 0 }}>
                  {orderedSessions.map((userSession) => (
                    <ListItem
                      key={userSession.id}
                      classes={{ root: classes.itemNested }}
                      divider={true}
                    >
                      <ListItemIcon classes={{ root: classes.itemIcon }}>
                        <ReceiptOutlined fontSize="small" />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <div>
                            <div className={classes.created}>
                              {nsdt(userSession.created)}
                            </div>
                            <div className={classes.ttl}>
                              {Math.round(userSession.ttl / 60)} {t('minutes')}
                            </div>
                          </div>
                        }
                      />
                      <ListItemSecondaryAction>
                        <IconButton
                          aria-label="Kill"
                          onClick={this.handleOpenKillSession.bind(
                            this,
                            userSession.id,
                          )}
                          size="large"
                        >
                          <Delete />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              </div>
            );
          })}
        </List>
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
      </div>
    );
  }
}

SessionsListComponent.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  nsdt: PropTypes.func,
  data: PropTypes.object,
};

export const sessionsListQuery = graphql`
  query SessionsListQuery {
    ...SessionsList_sessions
  }
`;

const SessionsList = createRefetchContainer(
  SessionsListComponent,
  {
    data: graphql`
      fragment SessionsList_sessions on Query {
        sessions {
          user {
            id
            name
            user_email
          }
          sessions {
            id
            created
            ttl
          }
        }
      }
    `,
  },
  sessionsListQuery,
);

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(SessionsList);
