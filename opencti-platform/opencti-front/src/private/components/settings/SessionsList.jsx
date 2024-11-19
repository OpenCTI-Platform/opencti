import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { DeleteOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import { interval } from 'rxjs';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { graphql, createRefetchContainer } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation } from '../../../relay/environment';
import { FIVE_SECONDS, timestamp } from '../../../utils/Time';
import { userSessionKillMutation } from './users/User';
import ItemIcon from '../../../components/ItemIcon';
import Transition from '../../../components/Transition';
import { useFormatter } from '../../../components/i18n';

const interval$ = interval(FIVE_SECONDS);

const useStyles = makeStyles((theme) => ({
  item: {},
  itemNested: {
    paddingLeft: theme.spacing(4),
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
}));

const SessionsListComponent = ({ relay, data, keyword }) => {
  const classes = useStyles();
  const { t_i18n, nsdt } = useFormatter();
  const [displayKillSession, setDisplayKillSession] = useState(false);
  const [killing, setKilling] = useState(false);
  const [sessionToKill, setSessionToKill] = useState(null);

  useEffect(() => {
    const subscription = interval$.subscribe(() => relay.refetch());
    return () => {
      subscription.unsubscribe();
    };
  }, []);

  const handleOpenKillSession = (session) => {
    setDisplayKillSession(true);
    setSessionToKill(session);
  };

  const handleCloseKillSession = () => {
    setDisplayKillSession(false);
    setSessionToKill(null);
  };

  const submitKillSession = () => {
    setKilling(true);
    commitMutation({
      mutation: userSessionKillMutation,
      variables: {
        id: sessionToKill,
      },
      onCompleted: () => {
        setKilling(false);
        handleCloseKillSession();
      },
      onError: () => {
        setKilling(false);
      },
    });
  };

  const sortByNameCaseInsensitive = (a, b) => a.user.name.toLowerCase().localeCompare(b.user.name.toLowerCase());
  const filterByKeyword = (n) => keyword === ''
    || n.user.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
  const sessions = (data.sessions ?? []).filter(filterByKeyword).toSorted(sortByNameCaseInsensitive);

  return (
    <>
      <List
        component="nav"
        aria-labelledby="nested-list-subheader"
        className={classes.root}
      >
        {sessions.map((session) => {
          const { user, sessions: userSessions } = session;
          const orderedSessions = userSessions.toSorted(
            (a, b) => timestamp(a.created) - timestamp(b.created),
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
                <ListItemIcon>
                  <ItemIcon type="User" />
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
                    <ListItemIcon>
                      <ItemIcon type="Session" />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <div>
                          <div className={classes.created}>
                            {nsdt(userSession.created)}
                          </div>
                          <div className={classes.ttl}>
                            {Math.round(userSession.ttl / 60)}{' '}
                            {t_i18n('minutes left')} /{' '}
                            {Math.round(userSession.originalMaxAge / 60)}
                          </div>
                        </div>
                      }
                    />
                    <ListItemSecondaryAction>
                      <IconButton
                        aria-label="Kill"
                        onClick={() => handleOpenKillSession(userSession.id)}
                        size="large"
                        color="primary"
                      >
                        <DeleteOutlined />
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
        open={displayKillSession}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseKillSession}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to kill this session?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseKillSession}
            disabled={killing}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitKillSession}
            color="primary"
            disabled={killing}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export const sessionsListQuery = graphql`
  query SessionsListQuery {
    ...SessionsList_sessions
  }
`;

export default createRefetchContainer(
  SessionsListComponent,
  {
    data: graphql`
      fragment SessionsList_sessions on Query {
        sessions {
          user {
            id
            name
          }
          sessions {
            id
            created
            ttl
            originalMaxAge
          }
        }
      }
    `,
  },
  sessionsListQuery,
);
