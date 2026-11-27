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
  notifyWarning: (text: unknown) => MESSENGER$.next([{ type: 'warning', text }]),
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
// The backend fills the base path in a meta element of index.html, as the CSP blocks inline scripts.
const basePath = document.querySelector<HTMLMetaElement>('meta[name="base-path"]')?.content ?? '';
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
      // Never give up reconnecting: the socket is also the presence of the tab for the platform
      // (logout when the last tab is closed), a tab without socket would silently stop being tracked.
      retryAttempts: Infinity,
      // Exponential backoff with jitter, capped to keep reconnecting promptly after a long outage
      retryWait: (retries) => new Promise((resolve) => {
        setTimeout(resolve, Math.min(1000 * 2 ** retries, 10000) + Math.floor(Math.random() * 2700 + 300));
      }),
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
// Types whose id is the id of an object of another type, so they are stored under `Typename:id`.
// Connector: a sync's built-in twin connector shares the sync id (queue key).
// The others are light projections reusing the id of the entity they describe (User, Group, Organization,
// MarkingDefinition, JsonMapper, CsvMapper, feed, deleted element...).
const namespacedTypenames = new Set([
  'MeUser', 'PublicSettings', 'Connector',
  'Creator', 'Assignee', 'Participant', 'Member', 'MeOrganization', 'MemberGroupRestriction', 'RequestAccessMember',
  'MarkingDefinitionShort', 'IngestionJsonMapperFromImport', 'IngestionDeduplicationUsage', 'ConnectorConfiguration',
  'NotifierConnector', 'RemoteStreamCollection', 'OpenCtiFile', 'WorkflowEntityRef', 'DraftResolvedId', 'DeletedElement',
  'RepresentativeWithId', 'AttributeRef',
]);
// Types whose id is not unique among objects of the same type, so they are never normalized by id (Relay then keys
// them under their parent). Dashboard variables and presets, mapper representations: ids kept through duplication and
// import. DefaultValue, Attribute: the id is a raw value. PlaybookComponentPort: 'out' in every component.
// XtmCounterpartResult: one per product with the same id. BackgroundTaskError: no unique id.
const unkeyedTypenames = new Set([
  'DashboardVariable', 'DashboardPreset', 'CsvMapperRepresentation', 'JsonMapperRepresentation', 'DefaultValue',
  'Attribute', 'PlaybookComponentPort', 'XtmCounterpartResult', 'BackgroundTaskError',
]);
export const getDataID = (fieldValue: { id?: string } | null | undefined, typeName: string) => {
  const id = fieldValue?.id;
  if (!id || unkeyedTypenames.has(typeName)) return null;
  if (namespacedTypenames.has(typeName)) {
    return `${typeName}:${id}`;
  }
  return id;
};
export const environment = new Environment({ network, store, getDataID });

// Dev only: Relay only logs store id collisions in the console, which is easy to miss. Show each one once.
if (import.meta.env.DEV) {
  const typeCollision = /conflicting types `(\w+)` and `(\w+)`/;
  const reported = new Set<string>();
  const consoleError = console.error;
  // Merged in one toast, as the message bus keeps the last message of a burst and the toast shows one, and delayed,
  // as collisions found while the app boots come before the toast component listens.
  // ponytail: fixed delay, a replayed message bus if a collision on boot ever comes after it
  let pending: string[] = [];
  const flush = () => {
    MESSAGING$.notifyError(
      <>
        [dev] Relay store: {pending.join(' / ')}
        <br />
        Details in the console (filter &quot;conflicting&quot;), fix hints in relay/environment.tsx
      </>,
    );
    pending = [];
  };
  const notifyOnce = (key: string, text: string) => {
    if (!reported.has(key)) {
      reported.add(key);
      pending.push(text);
      if (pending.length === 1) setTimeout(flush, 3000);
    }
  };
  console.error = (...args: unknown[]) => {
    consoleError(...args);
    if (typeof args[0] !== 'string') return;
    const types = typeCollision.exec(args[0]);
    if (types) {
      // fix: classify the type in namespacedTypenames or unkeyedTypenames
      notifyOnce(`types:${types[1]}/${types[2]}`, `${types[1]} and ${types[2]} share an id`);
    }
  };
}

// Components
interface QueryRendererProps {
  variables?: Record<string, unknown>;
  query: GraphQLTaggedNode;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  render: (data: any) => ReactNode;
  fetchPolicy?: FetchPolicy;
}

type FetchQueryOptions = NonNullable<Parameters<typeof FQ>[3]>;

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

export const buildErrorMessages = (error: RelayError) => (error.res.errors ?? []).map(
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
  options?: FetchQueryOptions,
) => FQ<T>(environment, query, args, options);

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
        fullError: e,
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
        fullError: e,
      }));
    MESSAGING$.messages.next(messages);
  }
};
