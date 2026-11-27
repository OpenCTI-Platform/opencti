export interface GraphQLResponseError {
  message?: string;
  extensions?: {
    code?: string;
    data?: { reason?: string; [key: string]: unknown };
  };
}

type ThrownResponseError = { res?: { errors?: GraphQLResponseError[] }; data?: { res?: { errors?: GraphQLResponseError[] } } };

/**
 * Errors of the GraphQL response carried by an error the network layer throws: on the error itself, and on its
 * `data` for the errors thrown again on the way (the "retro" errors the error boundaries also read).
 * None for any other error.
 */
export const getGraphQLResponseErrors = (error: unknown): GraphQLResponseError[] => {
  const responseError = error as ThrownResponseError | null | undefined;
  return [...(responseError?.res?.errors ?? []), ...(responseError?.data?.res?.errors ?? [])];
};

/**
 * Only the messages of the GraphQL response, not the whole error of the network layer
 * ("Relay request for ... failed by the following reasons: ..."). The error's own message for any other error.
 */
export const getGraphQLResponseErrorsMessage = (error: Error): string => {
  const messages = getGraphQLResponseErrors(error).flatMap((e) => (e.message ? [e.message] : []));
  return messages.length > 0 ? messages.join(' ') : error.message;
};
