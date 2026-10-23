import { graphql } from 'react-relay';
import { commitMutation, defaultCommitMutation } from '../relay/environment';

const xtmHubLogMutation = graphql`
  mutation xtmHubLogMutation($message: String!) {
    frontendErrorLog(message: $message)
  }
`;

const loggedOriginPairs = new Set<string>();

export const logXtmHubIgnoredMessage = (receivedOrigin: string, expectedOrigin: string | null) => {
  const key = `${receivedOrigin}|${expectedOrigin}`;
  if (loggedOriginPairs.has(key)) {
    return;
  }
  loggedOriginPairs.add(key);
  commitMutation({
    mutation: xtmHubLogMutation,
    variables: {
      message: `XTM Hub: message ignored, it comes from "${receivedOrigin}" but the configured XTM Hub origin is "${expectedOrigin}"`,
    },
    ...defaultCommitMutation,
    onError: () => {},
  });
};
