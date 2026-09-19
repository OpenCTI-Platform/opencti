import { Environment, FetchPolicy, Observable, RecordSource, SelectorStoreUpdater, Store } from 'relay-runtime';
import type { GraphQLSubscriptionConfig } from 'relay-runtime';
import type { RequestParameters, Variables } from 'relay-runtime';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import React, { ReactNode } from 'react';
import { commitLocalUpdate as CLU, commitMutation as CM, fetchQuery as FQ, QueryRenderer as QR, requestSubscription as RS } from 'react-relay';
import { urlMiddleware, RelayNetworkLayer } from 'react-relay-network-modern';
import type { SubscribeFunction } from 'react-relay-network-modern';
import * as R from 'ramda';
import { createClient } from 'graphql-ws';
import uploadMiddleware from './uploadMiddleware';
import type { RelayError } from './relayTypes';

declare global {
  interface Window {
    BASE_PATH?: string;
  }
}

interface ServiceMessage {
  type: string;
  text?: unknown;
  fullError?: unknown;
}

// Service bus
const MESSENGER$ = new Subject<ServiceMessage[]>().pipe(
  debounce(() => timer(500)),
) as Subject<ServiceMessage[]>;
export const MESSAGING$ = {
  messages: MESSENGER$,
  notifyError: (text: unknown) => MESSENGER$.next([{ type: 'error', text }]),
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- untyped error API, see the note on commitMutation
  notifyRelayError: (error: any) => {
    const errors: RelayError['res']['errors'] = error.res.errors ?? [];
    const messages = errors.map((e) => ({
      type: 'error',
      text: e.message,
      fullError: e,
    }));
    MESSENGER$.next(messages);
  },
  notifyCustomRelayError: (error: RelayError, errorMessageMap: Record<string, string | ReactNode>) => {
    const messages = (error.res.errors ?? []).map((e) => ({
      type: 'error',
      text: errorMessageMap[e.name ?? ''] ?? e.message,
      fullError: e,
    }));
    MESSENGER$.next(messages);
  },
  notifySuccess: (text: unknown) => MESSENGER$.next([{ type: 'message', text }]),
  notifyNLQ: (text: unknown) => MESSENGER$.next([{ type: 'nlq', text }]),
  toggleNav: new Subject(),
  redirect: new Subject(),
};

// Default application exception.
export class ApplicationError extends Error {
  data: unknown;

  constructor(errors: unknown) {
    super();
    this.data = errors;
  }
}

// Network
const basePath = window.BASE_PATH ?? '';
const isEmptyPath = R.isEmpty(basePath);
const contextPath = isEmptyPath || basePath === '/' ? '' : basePath;
export const APP_BASE_PATH = isEmptyPath || contextPath.startsWith('/') ? contextPath : `/${contextPath}`;

// Create Network
let subscriptionClient: ReturnType<typeof createClient> | undefined;
const loc = window.location;
const isSecure = loc.protocol === 'https:' ? 's' : '';
const subscriptionUrl = `ws${isSecure}://${loc.host}${APP_BASE_PATH}/graphql`;
const subscribeFn = (request: RequestParameters, variables: Variables) => {
  if (!subscriptionClient) {
    // Lazy creation of the subscription client to connect only after auth
    subscriptionClient = createClient({
      url: subscriptionUrl,
    });
  }
  const client = subscriptionClient;
  return Observable.create((sink) => {
    return client.subscribe({
      query: request.text as string,
      operationName: request.name,
      variables,
    }, sink);
  });
};
const fetchMiddleware = urlMiddleware({
  url: `${APP_BASE_PATH}/graphql`,
  credentials: 'same-origin',
  // --- to add when we enable csrfPrevention in ApolloServer ---
  // headers: (request) => {
  //   return { 'x-apollo-operation-name': request.operation.operationKind };
  // },
  // -----------
});
const network = new RelayNetworkLayer([fetchMiddleware, uploadMiddleware()], {
  subscribeFn: subscribeFn as unknown as SubscribeFunction,
});
const store = new Store(new RecordSource());
const namespacedTypenames = new Set(['MeUser', 'PublicSettings']);
const getDataID = (fieldValue: { id?: string } | null | undefined, typeName: string) => {
  const id = fieldValue?.id;
  if (!id) return null;
  if (namespacedTypenames.has(typeName)) {
    return `${typeName}:${id}`;
  }
  return id;
};
export const environment = new Environment({ network, store, getDataID });

// Components
interface QueryRendererProps {
  variables?: Record<string, unknown>;
  query: GraphQLTaggedNode;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  render: (data: any) => ReactNode;
  fetchPolicy?: FetchPolicy;
}

export const QueryRenderer = ({
  variables,
  query,
  render,
  fetchPolicy,
}: QueryRendererProps) => {
  return (
    <QR
      environment={environment}
      query={query}
      variables={variables ?? {}}
      fetchPolicy={fetchPolicy}
      render={(data) => {
        const { error } = data;
        if (error) {
          throw new ApplicationError(error);
        }
        return render(data);
      }}
    />
  );
};

const buildErrorMessages = (error: RelayError) => (error.res.errors ?? []).map(
  (e) => ({
    type: 'error',
    text: e?.data?.reason ?? e.message,
  }));

const FORCE_PASSWORD_CHANGE_ROUTE = '/dashboard/change-password';

export const defaultCommitMutation = {
  updater: undefined,
  optimisticUpdater: undefined,
  optimisticResponse: undefined,
  onCompleted: undefined,
  onError: undefined,
  setSubmitting: undefined,
};

export const relayErrorHandling = (
  error: Error,
  setSubmitting?: (submitted: boolean) => void,
  onError?: (e: Error, messages: { type: string; text: unknown }[]) => void,
) => {
  if (setSubmitting) setSubmitting?.(false);
  const relayError = error as unknown as RelayError;
  if (relayError && relayError.res && relayError.res.errors) {
    const passwordChangeRequired = relayError.res.errors.some(
      (e) => e?.extensions?.code === 'PASSWORD_CHANGE_REQUIRED',
    );
    if (passwordChangeRequired) {
      const alreadyOnForcePasswordChange = window.location.pathname.startsWith(FORCE_PASSWORD_CHANGE_ROUTE);
      if (!alreadyOnForcePasswordChange) {
        MESSAGING$.redirect.next(FORCE_PASSWORD_CHANGE_ROUTE);
      }
      return;
    }
    const authRequired = relayError.res.errors.filter(
      (e) => (e?.data?.type ?? e.message) === 'authentication',
    );
    if (authRequired.length > 0) {
      MESSAGING$.notifyError('Unauthorized action, please refresh your browser');
    } else if (onError) {
      const messages = buildErrorMessages(relayError);
      MESSAGING$.messages.next(messages);
      onError(error, messages);
    } else {
      const messages = buildErrorMessages(relayError);
      MESSAGING$.messages.next(messages);
    }
  }
};

// Relay functions
// The mutation API of this module is untyped, and so is the error shape its
// callers hand back. Both are spelled `any` rather than left implicit, so the
// remaining work is greppable while the rest of the workspace stays strict.
/* eslint-disable @typescript-eslint/no-explicit-any */
interface CommitMutationArgs {
  mutation: any;
  variables: any;
  updater?: any;
  optimisticUpdater?: any;
  optimisticResponse?: any;
  onCompleted?: any;
  onError?: any;
  setSubmitting?: any;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

export const commitMutation = ({
  mutation,
  variables,
  updater,
  optimisticUpdater,
  optimisticResponse,
  onCompleted,
  onError,
  setSubmitting,
}: CommitMutationArgs) => CM(environment, {
  mutation,
  variables,
  updater,
  optimisticUpdater,
  optimisticResponse,
  onCompleted,
  onError: (error) => relayErrorHandling(error, setSubmitting, onError),
});

export const requestSubscription = <T extends OperationType>(args: GraphQLSubscriptionConfig<T>) => RS<T>(environment, args);

export const fetchQuery = <T extends OperationType>(
  query: GraphQLTaggedNode,
  args: T['variables'] = {},
) => FQ<T>(environment, query, args);

export const commitLocalUpdate = (updater: SelectorStoreUpdater) => CLU(environment, updater);

export const handleErrorInForm = (
  e: Error,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- untyped error API, see the note on commitMutation
  setErrors: (e: any) => void,
) => {
  const error = e as unknown as RelayError;
  const formattedError = R.head(error.res.errors ?? []);
  if (formattedError?.data && formattedError.data.field) {
    setErrors({
      [formattedError.data.field]:
      formattedError.data.message || formattedError.data.reason,
    });
  } else {
    const messages = (error.res.errors ?? []).map(
      (e) => ({
        type: 'error',
        text: e?.data?.reason ?? e.message,
      }));
    MESSAGING$.messages.next(messages);
  }
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- untyped error API, see the note on commitMutation
export const handleError = (error: any) => {
  if (error && error.res && error.res.errors) {
    const errors: RelayError['res']['errors'] = error.res.errors ?? [];
    const messages = errors.map(
      (e) => ({
        type: 'error',
        text: e?.data?.message ?? e.message,
      }));
    MESSAGING$.messages.next(messages);
  }
};
