import { Environment, RecordSource, Store, Observable } from 'relay-runtime';
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
import { map, isEmpty, difference, filter, pathOr, isNil } from 'ramda';
import {
  urlMiddleware,
  RelayNetworkLayer,
} from 'react-relay-network-modern/node8';
import * as R from 'ramda';
import uploadMiddleware from './uploadMiddleware';

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

export const fileUri = (fileImport) => `${APP_BASE_PATH}${fileImport}`; // No slash here, will be replace by the builder

// Create Network
let subscriptionClient;
const loc = window.location;
const isSecure = loc.protocol === 'https:' ? 's' : '';
const subscriptionUrl = `ws${isSecure}://${loc.host}${APP_BASE_PATH}/graphql`;
const subscribeFn = (request, variables) => {
  if (!subscriptionClient) {
    // Lazy creation of the subscription client to connect only after auth
    subscriptionClient = new SubscriptionClient(subscriptionUrl, {
      reconnect: true,
    });
  }
  const subscribeObservable = subscriptionClient.request({
    query: request.text,
    operationName: request.name,
    variables,
  });
  return Observable.from(subscribeObservable);
};
const fetchMiddleware = urlMiddleware({
  url: `${APP_BASE_PATH}/graphql`,
  credentials: 'same-origin',
});
const network = new RelayNetworkLayer([fetchMiddleware, uploadMiddleware()], {
  subscribeFn,
});
const store = new Store(new RecordSource());
export const environment = new Environment({ network, store });

// Components
export class QueryRenderer extends Component {
  render() {
    const { variables, query, render, managedErrorTypes } = this.props;
    return (
      <QR
        environment={environment}
        query={query}
        variables={variables}
        render={(data) => {
          const { error } = data;
          const types = error ? map((e) => e.name, error) : [];
          const unmanagedErrors = difference(types, managedErrorTypes || []);
          if (!isEmpty(unmanagedErrors)) throw new ApplicationError(error);
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

const buildErrorMessages = (error) => map(
  (e) => ({
    type: 'error',
    text: pathOr(e.message, ['data', 'reason'], e),
  }),
  error.res.errors,
);

// Relay functions
export const commitMutation = ({
  mutation,
  variables,
  updater,
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
      } else if (onError) {
        const messages = buildErrorMessages(error);
        onError(error, messages);
      } else {
        const messages = buildErrorMessages(error);
        MESSAGING$.messages.next(messages);
      }
    }
  },
});

export const requestSubscription = (args) => RS(environment, args);

export const fetchQuery = (query, args) => FQ(environment, query, args);

export const commitLocalUpdate = (updater) => CLU(environment, updater);

export const handleErrorInForm = (error, setErrors) => {
  const formattedError = R.head(error.res.errors);
  if (formattedError.data && formattedError.data.field) {
    setErrors({
      [formattedError.data.field]:
        formattedError.data.message || formattedError.data.reason,
    });
  } else {
    const messages = map(
      (e) => ({
        type: 'error',
        text: pathOr(e.message, ['data', 'reason'], e),
      }),
      error.res.errors,
    );
    MESSAGING$.messages.next(messages);
  }
};
