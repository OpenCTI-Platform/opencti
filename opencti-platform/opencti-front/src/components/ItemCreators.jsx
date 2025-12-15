import React from 'react';
import Button from '@common/button/Button';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import Security from '../utils/Security';
import { SETTINGS_SETACCESSES } from '../utils/hooks/useGranted';

const systemUsers = [
  '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505', // SYSTEM
  '82ed2c6c-eb27-498e-b904-4f2abc04e05f', // RETENTION MANAGER
  'c49fe040-2dad-412d-af07-ce639204ad55', // AUTOMATION MANAGER
  'f9d7b43f-b208-4c56-8637-375a1ce84943', // RULE MANAGER
  '31afac4e-6b99-44a0-b91b-e04738d31461', // REDACTED USER
];

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
            key={creator.id}
            needs={[SETTINGS_SETACCESSES]}
            placeholder={(
              <Button
                variant="outlined"
                size="small"
                classes={{ root: classes.button }}
                style={{ cursor: 'default' }}
              >
                {creator.name}
              </Button>
            )}
          >
            {systemUsers.includes(creator.id) ? (
              <Button
                variant="secondary"
                size="small"
                classes={{ root: classes.button }}
                style={{ cursor: 'default' }}
              >
                {creator.name}
              </Button>
            ) : (
              <Button
                variant="secondary"
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
