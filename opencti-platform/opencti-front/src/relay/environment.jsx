import { Environment, Observable, RecordSource, Store } from 'relay-runtime';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import React, { Component } from 'react';
import { commitLocalUpdate as CLU, commitMutation as CM, fetchQuery as FQ, QueryRenderer as QR, requestSubscription as RS } from 'react-relay';
import * as PropTypes from 'prop-types';
import { urlMiddleware, RelayNetworkLayer } from 'react-relay-network-modern';
import * as R from 'ramda';
import { RelayNetworkLayer, urlMiddleware, } from 'react-relay-network-modern';
import { createClient } from 'graphql-ws';
import uploadMiddleware from './uploadMiddleware';

// Service bus
const MESSENGER$ = new Subject().pipe(debounce(() => timer(500)));
export const MESSAGING$ = {
  messages: MESSENGER$,
  notifyError: (text) => MESSENGER$.next([{ type: 'error', text }]),
  notifySuccess: (text) => MESSENGER$.next([{ type: 'message', text }]),
  toggleNav: new Subject(),
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
const isEmptyPath = R.isNil(window.BASE_PATH) || R.isEmpty(window.BASE_PATH);
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
    subscriptionClient = createClient({
      url: subscriptionUrl,
    });
  }
  return Observable.create((sink) => {
    return subscriptionClient.subscribe({
      query: request.text,
      operationName: request.name,
      variables,
    }, sink);
  });
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
    const { variables, query, render } = this.props;
    return (
      <QR
        environment={environment}
        query={query}
        variables={variables}
        render={(data) => {
          const { error } = data;
          if (error) {
            throw new ApplicationError(error);
          }
          return render(data);
        }}
      />
    );
  }
}

QueryRenderer.propTypes = {
  variables: PropTypes.object,
  render: PropTypes.func,
  query: PropTypes.object,
};

const buildErrorMessages = (error) => R.map(
  (e) => ({
    type: 'error',
    text: R.pathOr(e.message, ['data', 'reason'], e),
  }),
  error.res.errors,
);

export const defaultCommitMutation = {
  updater: undefined,
  optimisticUpdater: undefined,
  optimisticResponse: undefined,
  onCompleted: undefined,
  onError: undefined,
  setSubmitting: undefined,
};

export const relayErrorHandling = (error, setSubmitting, onError) => {
  if (setSubmitting) setSubmitting(false);
  if (error && error.res && error.res.errors) {
    const authRequired = R.filter(
      (e) => R.pathOr(e.message, ['data', 'type'], e) === 'authentication',
      error.res.errors,
    );
    if (!R.isEmpty(authRequired)) {
      MESSAGING$.notifyError('Unauthorized action, please refresh your browser');
    } else if (onError) {
      const messages = buildErrorMessages(error);
      MESSAGING$.messages.next(messages);
      onError(error, messages);
    } else {
      const messages = buildErrorMessages(error);
      MESSAGING$.messages.next(messages);
    }
  }
};

export const extractSimpleError = (error) => {
  if (error && error.res && error.res.errors) {
    const messages = buildErrorMessages(error);
    return messages[0].text;
  }
  return 'Unknown error';
};

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
  onError: (error) => relayErrorHandling(error, setSubmitting, onError),
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
    const messages = R.map(
      (e) => ({
        type: 'error',
        text: R.pathOr(e.message, ['data', 'reason'], e),
      }),
      error.res.errors,
    );
    MESSAGING$.messages.next(messages);
  }
};

export const handleError = (error) => {
  if (error && error.res && error.res.errors) {
    const messages = R.map(
      (e) => ({
        type: 'error',
        text: R.pathOr(e.message, ['data', 'message'], e),
      }),
      error.res.errors,
    );
    MESSAGING$.messages.next(messages);
  }
};
