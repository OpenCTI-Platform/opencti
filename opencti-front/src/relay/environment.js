import {Environment, Network, RecordSource, Store,} from 'relay-runtime';
import {installRelayDevTools} from 'relay-devtools';

const __DEV__ = process.env.NODE_ENV === 'development';
if (__DEV__) installRelayDevTools();

function fetchQuery(operation, variables) {
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
    });
}

const environment = new Environment({
    network: Network.create(fetchQuery),
    store: new Store(new RecordSource()),
});

export default environment;