import React from 'react';
import { ApolloSandbox } from '@apollo/sandbox/react';
import makeStyles from '@mui/styles/makeStyles';
import { EmbeddableSandboxOptions } from '@apollo/sandbox/src/EmbeddedSandbox';

const useStyles = makeStyles({
  sandbox: {
    width: '100%',
    height: '100%',
  },
});

const SandBox = () => {
  const classes = useStyles();
  const sandboxOpts: Omit<EmbeddableSandboxOptions, 'target'> = {
    initialEndpoint: 'http://localhost:4000/graphql',
    initialState: {
      includeCookies: true,
    },
  };

  return (
    <ApolloSandbox
      className={classes.sandbox}
      {...sandboxOpts}
    />
  );
};

export default SandBox;
