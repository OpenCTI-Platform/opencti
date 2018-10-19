import express from 'express';
import {ApolloServer} from 'apollo-server-express';
// noinspection NodeJsCodingAssistanceForCoreModules
import http from 'http';
import schema from './schema/schema';
import bodyParser from 'body-parser';
import {driver} from './database/index';
import {createTerminus} from '@godaddy/terminus';
import {verify} from 'jsonwebtoken';
import conf from './config/conf';
import passport from './config/security';
import cookieParser from 'cookie-parser';
import {AuthenticationError} from 'apollo-server-express';
import {findByTokenId} from "./domain/user";

// noinspection JSUnresolvedVariable
const devMode = process.env.NODE_ENV === 'development';

let app = express();
app.use(cookieParser());

// #### Login
let urlencodedParser = bodyParser.urlencoded({extended: true});
// ## Local strategy
app.post('/auth/api', urlencodedParser, passport.initialize(), function (req, res, next) {
    passport.authenticate('local', function (err, token) {
        if (err) res.status(400).send(err);
        if (!token) res.status(400).send(err);
        res.send(token);
    })(req, res, next);
});
app.get('/auth/:provider', function (req, res, next) {
    let provider = req.params.provider;
    passport.authenticate(provider)(req, res, next)
});
app.get('/auth/:provider/callback', urlencodedParser, passport.initialize(), function (req, res, next) {
    let provider = req.params.provider;
    passport.authenticate(provider, function (err, token) {
        if (err) return res.status(400).send(err);
        if (!token) return res.status(400).send(err);
        res.cookie('opencti_token', token, {httpOnly: false, secure: !devMode});
        res.redirect('/private');
    })(req, res, next);
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

const authentication = async (token) => {
    let user;
    try {
        let decodedToken = verify(token, conf.get("jwt:secret"));
        user = await findByTokenId(decodedToken.id);
    } catch (err) {
        if (devMode) { // In dev mode, inject a JWT token to be automatically 'logged'
            user = await findByTokenId(conf.get('jwt:dev_token'));
        } else {
            throw new AuthenticationError('Authentication required');
        }
    }
    return {user}
};

const extractTokenFromBearer = (bearer) => {
    return bearer && bearer.length > 10 ? bearer.substring('Bearer '.length) : null;
};

const server = new ApolloServer({
    schema: schema,
    context: function ({req}) {
        if (!req) return undefined; //Req can be null only for websocket subscription.
        //Authentication token can come from 'opencti cookie' or 'Authorization header'
        let token = req.cookies ? req.cookies.opencti_token : null;
        token = token ? token : extractTokenFromBearer(req.headers.authorization);
        return authentication(token);
    },
    formatError: error => {
        delete error.extensions.exception;
        return error;
    },
    subscriptions: { //https://www.apollographql.com/docs/apollo-server/features/subscriptions.html
        onConnect: (connectionParams) => {
            return authentication(extractTokenFromBearer(connectionParams.authorization));
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
