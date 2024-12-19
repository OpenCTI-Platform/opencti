import React from 'react';
import { ApolloSandbox } from '@apollo/sandbox/react';

const SandBox = () => {
  return (
    <ApolloSandbox
      initialEndpoint='http://localhost:4000'
    />
  );
};

export default SandBox;
