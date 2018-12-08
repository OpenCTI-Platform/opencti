import {
  Environment, Network, RecordSource, Store,
} from 'relay-runtime';
// eslint-disable-next-line import/no-extraneous-dependencies
import { installRelayDevTools } from 'relay-devtools';
import RelayQueryResponseCache from 'relay-runtime/lib/RelayQueryResponseCache';
import { SubscriptionClient } from 'subscriptions-transport-ws';
import { execute } from 'apollo-link';
import { WebSocketLink } from 'apollo-link-ws';
import Cookies from 'universal-cookie';

const GRAPHQL_SUBSCRIPTION_ENDPOINT = 'ws://localhost:4000/graphql';
const IN_DEV_MODE = process.env.NODE_ENV === 'development';
if (IN_DEV_MODE) installRelayDevTools();

const oneMinute = 60 * 1000;
const cache = new RelayQueryResponseCache({ size: 250, ttl: oneMinute });

function fetchQuery(operation, variables, cacheConfig) {
  const queryID = operation.text;
  // const isMutation = operation.operationKind === 'mutation';
  const isQuery = operation.operationKind === 'query';
  const forceFetch = cacheConfig && cacheConfig.force;

  // Try to get data from cache on queries
  const fromCache = cache.get(queryID, variables);
  if (isQuery && fromCache !== null && !forceFetch) {
    return fromCache;
  }

  // Otherwise, fetch data from server
  return fetch('/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      query: operation.text,
      variables,
    }),
  }).then(response => response.json());/* .then(json => {
        // Update cache on queries
        if (isQuery && json) {
            cache.set(queryID, variables, json);
        }
        // Clear cache on mutations
        if (isMutation) {
            cache.clear();
        }
        console.log('json', json);
        return json;
    }); */
}

const cookies = new Cookies();
const subscriptionClient = new SubscriptionClient(GRAPHQL_SUBSCRIPTION_ENDPOINT, {
  reconnect: true,
  connectionParams: {
    authorization: `Bearer ${cookies.get('opencti_token')}`,
  },
});
const subscriptionLink = new WebSocketLink(subscriptionClient);

const networkSubscriptions = (operation, variables) => execute(subscriptionLink, {
  query: operation.text,
  variables,
});

const environment = new Environment({
  network: Network.create(fetchQuery, networkSubscriptions),
  store: new Store(new RecordSource()),
});

export default environment;
