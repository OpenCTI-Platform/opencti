import {
  Environment, RecordSource, Store, Observable,
} from 'relay-runtime';
// eslint-disable-next-line import/no-extraneous-dependencies
import { installRelayDevTools } from 'relay-devtools';
import { SubscriptionClient } from 'subscriptions-transport-ws';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import React, { Component } from 'react';
import {
  commitLocalUpdate as CLU,
  commitMutation as CM,
  QueryRenderer as QR,
  requestSubscription as RS,
  fetchQuery as FQ,
} from 'react-relay';
import * as PropTypes from 'prop-types';
import {
  map, isEmpty, difference, filter, pathOr, isNil,
} from 'ramda';
import {
  urlMiddleware,
  RelayNetworkLayer,
} from 'react-relay-network-modern/node8';
import uploadMiddleware from './uploadMiddleware';
import { toastGenericError } from '../utils/bakedToast';

// Dev tools
export const IN_DEV_MODE = process.env.NODE_ENV === 'development';
if (IN_DEV_MODE) installRelayDevTools();

// Service bus
const MESSENGER$ = new Subject().pipe(debounce(() => timer(500)));
export const MESSAGING$ = {
  messages: MESSENGER$,
  notifyError: (text) => MESSENGER$.next([{ type: 'error', text }]),
  notifySuccess: (text) => MESSENGER$.next([{ type: 'message', text }]),
  redirect: new Subject(),
};

// Default application exception.
export class ApplicationError extends Error {
  constructor(errors) {
    super();
    this.data = errors;
  }
}

// Network
const isEmptyPath = isNil(window.BASE_PATH) || isEmpty(window.BASE_PATH);
const contextPath = isEmptyPath || window.BASE_PATH === '/' ? '' : window.BASE_PATH;
export const APP_BASE_PATH = isEmptyPath || contextPath.startsWith('/') ? contextPath : `/${contextPath}`;
// Subscription
const loc = window.location;
const serverUrl = new URL(
  process.env.REACT_APP_GRAPHQL_HOST ? process.env.REACT_APP_GRAPHQL_HOST : loc.host,
);
export const SERVER_URL = serverUrl.origin;
const isSecure = serverUrl.protocol === 'https:' ? 's' : '';

const subscriptionClient = new SubscriptionClient(
  `ws${isSecure}://${serverUrl.host}/graphql`,
  {
    reconnect: true,
  },
);

const subscribeFn = (request, variables) => {
  const subscribeObservable = subscriptionClient.request({
    query: request.text,
    operationName: request.name,
    variables,
  });
  // Important: Convert subscriptions-transport-ws observable type to Relay's
  return Observable.from(subscribeObservable);
};

const network = new RelayNetworkLayer(
  [
    urlMiddleware({
      url: `${SERVER_URL}/graphql`,
      credentials: 'include',
    }),
    uploadMiddleware(),
  ],
  { subscribeFn },
);

const store = new Store(new RecordSource());
// Activate the read from store then network
// store.holdGC();
export const environment = new Environment({
  network,
  store,
});

// Components
export class QueryRenderer extends Component {
  render() {
    const {
      variables, query, render, managedErrorTypes,
    } = this.props;
    return (
      <QR
        environment={environment}
        query={query}
        variables={variables}
        render={(data) => {
          const { error } = data;
          const types = error ? map((e) => e.name, error) : [];
          const unmanagedErrors = difference(types, managedErrorTypes || []);
          if (!isEmpty(unmanagedErrors)) {
            // This is to fix the error that constantly comes up when the user is not authenticated
            // when accessing the site. This is the first query to be run for any page so should be
            // binary good or fail
            if (query.operation.name === 'RootPrivateQuery') {
              render(error);
            } else {
              toastGenericError('Query Error');
              throw new ApplicationError(error);
            }
          }
          return render(data);
        }}
      />
    );
  }
}
QueryRenderer.propTypes = {
  managedErrorTypes: PropTypes.array,
  variables: PropTypes.object,
  render: PropTypes.func,
  query: PropTypes.object,
};

// Relay functions
export const commitMutation = ({
  mutation,
  variables,
  updater,
  pathname,
  optimisticUpdater,
  optimisticResponse,
  onCompleted,
  onError,
  setSubmitting,
}) => CM(environment, {
  mutation,
  variables,
  updater,
  optimisticUpdater,
  optimisticResponse,
  onCompleted,
  onError: (error) => {
    if (setSubmitting) setSubmitting(false);
    if (error && error.res && error.res.errors) {
      const authRequired = filter(
        (e) => pathOr(e.message, ['data', 'type'], e) === 'authentication',
        error.res.errors,
      );
      if (!isEmpty(authRequired)) {
        MESSAGING$.notifyError(
          'Unauthorized action, please refresh your browser',
        );
      } else {
        const messages = map(
          (e) => ({
            type: e?.extensions?.code || e?.name,
            message: pathOr(e.message, ['data', 'reason'], e),
            pathname,
          }),
          error.res.errors,
        );
        MESSAGING$.messages.next(messages);
        if (onError) onError(error);
      }
    }
  },
});

export const requestSubscription = (args) => RS(environment, args);

export const fetchQuery = (query, args) => FQ(environment, query, args);

export const commitLocalUpdate = (updater) => CLU(environment, updater);
