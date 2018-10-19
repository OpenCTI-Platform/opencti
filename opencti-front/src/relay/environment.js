import {Environment, Network, RecordSource, Store,} from 'relay-runtime';
import {installRelayDevTools} from 'relay-devtools';
import RelayQueryResponseCache from 'relay-runtime/lib/RelayQueryResponseCache';

const __DEV__ = process.env.NODE_ENV === 'development';
if (__DEV__) installRelayDevTools();

const oneMinute = 60 * 1000;
const cache = new RelayQueryResponseCache({size: 250, ttl: oneMinute});

function fetchQuery(operation, variables, cacheConfig,) {
    const queryID = operation.text;
    const isMutation = operation.operationKind === 'mutation';
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
    }).then(response => {
        return response.json();
    }).then(json => {
        // Update cache on queries
        if (isQuery && json) {
            cache.set(queryID, variables, json);
        }
        // Clear cache on mutations
        if (isMutation) {
            cache.clear();
        }
        return json;
    });
}

const environment = new Environment({
    network: Network.create(fetchQuery),
    store: new Store(new RecordSource()),
});

export default environment;