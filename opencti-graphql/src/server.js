import express from 'express';
import {ApolloServer} from 'apollo-server-express';
// noinspection NodeJsCodingAssistanceForCoreModules
import http from 'http';
import schema from './schema/schema';
import bodyParser from 'body-parser';
import {driver} from './database/index';
import {createTerminus} from '@godaddy/terminus';
import {login} from "./domain/user";
import {verify} from 'jsonwebtoken';
import conf from './config/conf';

// noinspection JSUnresolvedVariable
const devMode = process.env.NODE_ENV === 'development';

let app = express();

// Publish some public information
app.get('/about', function (req, res) {
    res.send('Welcome to openCTI graphQL API');
});

// Login is not part of graphQL API
let urlencodedParser = bodyParser.urlencoded({extended: true});
app.post('/login', urlencodedParser, function (req, res) {
    let username = req.body.username;
    let password = req.body.password;
    login(username, password)
        .then((token) => res.send(token))
        .catch((err) => res.status(400).send(err));
});

function onSignal() {
    console.log('OpenCTI is starting cleanup');
    driver.close();
}

function onShutdown() {
    console.log('Cleanup finished, openCTI shutdown');
}

// noinspection JSUnusedGlobalSymbols
const options = {
    signal: 'SIGINT',
    timeout: 1000, // [optional = 1000] number of milliseconds before forcefull exiting
    onSignal, // [optional] cleanup function, returning a promise (used to be onSigterm)
    onShutdown
};

const authentication = (token) => {
    let user;
    try {
        user = verify(token, conf.get("jwt:secret"));
    } catch (err) {
        if (devMode) {     // In dev mode, inject a JWT token to be automatically 'logged'
            user = verify(conf.get('jwt:dev_token'), conf.get("jwt:secret"));
        } else {
            throw new Error("You need to be authenticated to access this schema!");
        }
    }
    return {user}
};

const server = new ApolloServer({
    schema: schema,
    context: function ({req}) {
        return req !== undefined ? authentication(req.headers.authorization) : null;
    },
    subscriptions: { //https://www.apollographql.com/docs/apollo-server/features/subscriptions.html
        onConnect: (connectionParams) => {
            return authentication(connectionParams.authorization)
        },
    },
});

server.applyMiddleware({app});
const httpServer = http.createServer(app);
server.installSubscriptionHandlers(httpServer);

let PORT = conf.get('app:port');
httpServer.listen(PORT, () => {
    createTerminus(httpServer, options);
    console.log(`🚀 Server ready at http://localhost:${PORT}${server.graphqlPath}`);
    console.log(`🚀 Subscriptions ready at ws://localhost:${PORT}${server.subscriptionsPath}`);
});
