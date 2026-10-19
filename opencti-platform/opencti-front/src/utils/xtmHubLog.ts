import { graphql } from 'react-relay';
import { commitMutation } from '../relay/environment';

const xtmHubLogMutation = graphql`
  mutation xtmHubLogMutation($message: String!) {
    frontendErrorLog(message: $message)
  }
`;

export const logXtmHubIgnoredMessage = (receivedOrigin: string, expectedOrigin: string | null) => {
  commitMutation({
    mutation: xtmHubLogMutation,
    variables: {
      message: `XTM Hub: message ignored, it comes from "${receivedOrigin}" but the configured XTM Hub origin is "${expectedOrigin}"`,
    },
    onError: () => {},
  });
};
