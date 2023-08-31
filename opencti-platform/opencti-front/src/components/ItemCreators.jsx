import React from 'react';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import Security from '../utils/Security';
import { SETTINGS_SETACCESSES } from '../utils/hooks/useGranted';

const useStyles = makeStyles(() => ({
  button: {
    margin: '0 7px 7px 0',
  },
}));

const ItemCreators = (props) => {
  const { creators } = props;
  const classes = useStyles();
  return (
    <>
      {creators.map((creator) => {
        return (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={
              <Button
                variant="outlined"
                size="small"
                classes={{ root: classes.button }}
                style={{ cursor: 'default' }}
              >
                {creator.name}
              </Button>
            }
          >
            {creator.id === '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505' ? (
              <Button
                variant="outlined"
                size="small"
                classes={{ root: classes.button }}
                style={{ cursor: 'default' }}
              >
                {creator.name}
              </Button>
            ) : (
              <Button
                variant="outlined"
                size="small"
                classes={{ root: classes.button }}
                component={Link}
                to={`/dashboard/settings/accesses/users/${creator.id}`}
              >
                {creator.name}
              </Button>
            )}
          </Security>
        );
      })}
    </>
  );
};

export default ItemCreators;
