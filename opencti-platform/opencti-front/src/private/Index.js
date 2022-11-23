import React, { useEffect, useState, useCallback } from 'react';
import * as PropTypes from 'prop-types';
import { makeStyles } from '@material-ui/core/styles';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Message from '../components/Message';
import { getAccount } from '../services/account.service';
import IndexRoutePath from './components/IndexRoutePath';

const useStyles = makeStyles((theme) => ({
  root: {
    minWidth: '100%',
    height: '100%',
  },
  contentOpen: {
    height: '100%',
    flexGrow: 1,
    backgroundColor: theme.palette.background.default,
    minWidth: 0,
    margin: '1rem 1rem 0 17rem',
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    overflow: 'hidden',
  },
  contentClose: {
    height: '100%',
    flexGrow: 1,
    backgroundColor: theme.palette.background.default,
    minWidth: 0,
    margin: '1rem 1rem 0 5.5rem',
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    overflow: 'hidden',
  },
  message: {
    display: 'flex',
    alignItems: 'center',
  },
  messageIcon: {
    marginRight: theme.spacing(1),
  },
  toolbar: theme.mixins.toolbar,
}));

const Index = ({ me }) => {
  const classes = useStyles();
  const [drawer, setDrawer] = useState(false);
  const [clientId, setClientId] = useState(localStorage.getItem('client_id'));
  const clearStorage = () => {
    localStorage.removeItem('client_id');
  };

  const drawerValue = useCallback((value) => {
    setDrawer(value);
  }, []);

  useEffect(() => {
    if (!clientId) {
      getAccount().then((res) => {
        const account = res.data;
        if (account) {
          const id = account.clients?.[0].client_id;
          localStorage.setItem('client_id', id);
          setClientId(id);
        } else {
          clearStorage();
        }
      });
    }
  }, [clientId]);
  return (
    <div className={classes.root}>
      <TopBar drawer={drawer} me={me || null} />
      <LeftBar
        clientId={clientId}
        setClientId={setClientId}
        drawerValue={drawerValue}
      />
      <main
        className={drawer ? classes.contentClose : classes.contentOpen}
      // style={{ paddingRight: 24 }}
      >
        <Message />
        <div className={classes.toolbar} />
        <IndexRoutePath me={me} />
      </main>
    </div>
  );
};

Index.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  retry: PropTypes.func,
  me: PropTypes.object,
};

export default Index;
