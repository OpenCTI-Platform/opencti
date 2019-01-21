import {
  Environment, Network, RecordSource, Store,
} from 'relay-runtime';
// eslint-disable-next-line import/no-extraneous-dependencies
import { installRelayDevTools } from 'relay-devtools';
import { SubscriptionClient } from 'subscriptions-transport-ws';
import { execute } from 'apollo-link';
import { WebSocketLink } from 'apollo-link-ws';
import Cookies from 'js-cookie';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import React, { Component } from 'react';
import {
  commitMutation as CM, QueryRenderer as QR, requestSubscription as RS, fetchQuery as FQ,
} from 'react-relay';
import * as PropTypes from 'prop-types';
import {
  map, isEmpty, difference, filter,
} from 'ramda';

export const MESSAGING$ = {
  errors: new Subject().pipe(debounce(() => timer(1000))),
  redirect: new Subject(),
};
const GRAPHQL_SUBSCRIPTION_ENDPOINT = 'ws://localhost:4000/graphql';
const IN_DEV_MODE = process.env.NODE_ENV === 'development';
if (IN_DEV_MODE) installRelayDevTools();


class ApplicationError extends Error {
  constructor(errors) {
    super();
    this.data = errors;
  }
}

// Network
function networkFetch(operation, variables) {
  return fetch('/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      query: operation.text,
      variables,
    }),
  }).then(response => response.json())
    .then((json) => {
      if (json.errors) {
        return Promise.reject(json.errors);
      }
      return Promise.resolve(json);
    });
}
const subscriptionClient = new SubscriptionClient(GRAPHQL_SUBSCRIPTION_ENDPOINT, {
  reconnect: true,
  connectionParams: {
    authorization: `Bearer ${Cookies.get('opencti_token')}`,
  },
});
const subscriptionLink = new WebSocketLink(subscriptionClient);
const networkSubscriptions = (operation, variables) => execute(subscriptionLink, {
  query: operation.text,
  variables,
});
const environment = new Environment({
  network: Network.create(networkFetch, networkSubscriptions),
  store: new Store(new RecordSource()),
});

// Components
export class QueryRenderer extends Component {
  render() {
    const {
      variables, query, render, managedErrorTypes,
    } = this.props;
    return (<QR environment={environment} query={query} variables={variables}
        render={(data) => {
          const { error } = data;
          const types = error ? map(e => e.name, error) : [];
          const unmanagedErrors = difference(types, managedErrorTypes || []);
          if (!isEmpty(unmanagedErrors)) throw new ApplicationError(error);
          return render(data);
        }}
    />);
  }
}
QueryRenderer.propTypes = {
  managedErrorTypes: PropTypes.array,
  variables: PropTypes.object,
  render: PropTypes.func,
  query: PropTypes.func,
};

// Relay functions
export const commitMutation = ({
  mutation, variables, updater, optimisticUpdater, onCompleted, onError, setSubmitting,
}) => CM(environment, {
  mutation,
  variables,
  updater,
  optimisticUpdater,
  onCompleted,
  onError: (errors) => {
    if (setSubmitting) setSubmitting(false);
    const authRequired = filter(e => e.data.type === 'authentication', errors);
    if (!isEmpty(authRequired)) {
      Cookies.remove('opencti_token');
      MESSAGING$.redirect.next('/login');
    } else {
      MESSAGING$.errors.next(errors);
      if (onError) onError(errors);
    }
  },
});

export const requestSubscription = args => RS(environment, args);

export const fetchQuery = (query, args) => FQ(environment, query, args);
