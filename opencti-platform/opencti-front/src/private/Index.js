import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { makeStyles } from '@material-ui/core/styles';
import LeftBar from './components/nav/LeftBar';
import Message from '../components/Message';
import { getAccount } from '../services/account.service';
import IndexRoutePath from './components/IndexRoutePath';

const useStyles = makeStyles((theme) => ({
  root: {
    minWidth: '100%',
    height: '100%',
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
  const [clientId, setClientId] = useState(localStorage.getItem('client_id'));
  const clearStorage = () => {
    localStorage.removeItem('client_id');
  };

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
      <LeftBar
        clientId={clientId}
        setClientId={setClientId}
      >
        <main
        // style={{ paddingRight: 24 }}
        >
          <Message />
          <div className={classes.toolbar} />
          <IndexRoutePath me={me} />
        </main>
      </LeftBar>

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
