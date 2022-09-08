import React, { useEffect, useState, useCallback } from 'react';
import * as PropTypes from 'prop-types';
import { makeStyles } from '@material-ui/core/styles';
import TopBarBreadcrumbs from './components/nav/TopBarBreadcrumbs';
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
    margin: '1.2rem 1rem 0 17rem',
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    overflowX: 'hidden',
  },
  contentClose: {
    height: '100%',
    flexGrow: 1,
    backgroundColor: theme.palette.background.default,
    minWidth: 0,
    margin: '1.2rem 1rem 0 5rem',
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    overflowX: 'hidden',
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

const Index = (me) => {
  const classes = useStyles();
  const [drawer, setDrawer] = useState(false);
  const [clientId, setClientId] = useState(localStorage.getItem('client_id'));
  const clearStorage = () => {
    localStorage.removeItem('token');
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
    const jwtToken = JSON.parse(atob(me.me.access_token.split('.')[1]));
    const expiration = ((jwtToken.exp - 60) * 1000) - Date.now();
    if (expiration >= 0) {
      setInterval(() => {
        localStorage.removeItem('token');
        me.retry();
      }, expiration);
    }
  }, [clientId]);
  return (
    <div className={classes.root}>
      <TopBarBreadcrumbs drawer={drawer} />
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
        <IndexRoutePath me={me}/>
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
