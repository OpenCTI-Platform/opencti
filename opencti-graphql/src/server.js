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

// Publish some public information
app.get('/about', function (req, res) {
    res.send('Welcome to openCTI graphQL API');
});

// #### Login
let urlencodedParser = bodyParser.urlencoded({extended: true});
// ## Local strategy
app.post('/auth/opencti', urlencodedParser, passport.initialize(), function (req, res, next) {
    passport.authenticate('local', function (err, user) {
        if (err) res.status(400).send(err);
        if (!user) res.status(400).send(err);
        res.cookie('opencti_token', user, {httpOnly: false, secure: true});
        res.redirect('/private');
    })(req, res, next);
});
// ## Facebook strategy
app.get('/auth/facebook', passport.authenticate('facebook', {scope: ['email']}));
app.get('/auth/facebook/callback', urlencodedParser, passport.initialize(), function (req, res, next) {
    passport.authenticate('facebook', function (err, user) {
        if (err) return res.status(400).send(err);
        if (!user) return res.status(400).send(err);
        res.cookie('opencti_token', user, {httpOnly: false, secure: true});
        res.redirect('/private');
    })(req, res, next);
});
// ## Google strategy
app.get('/auth/google', passport.authenticate('google'));
app.get('/auth/google/callback', urlencodedParser, passport.initialize(), function (req, res, next) {
    passport.authenticate('google', function (err, user) {
        if (err) return res.status(400).send(err);
        res.cookie('opencti_token', user, {httpOnly: false, secure: true});
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
        let token_id = verify(token, conf.get("jwt:secret"));
        user = await findByTokenId(token_id);
    } catch (err) {
        if (devMode) { // In dev mode, inject a JWT token to be automatically 'logged'
            user = await findByTokenId(conf.get('jwt:dev_token'));
        } else {
            throw new AuthenticationError('Authentication required');
        }
    }
    return {user}
};

const server = new ApolloServer({
    schema: schema,
    context: function ({req}) {
        let token = req && req.cookies ? req.cookies.opencti_token : null;
        return authentication(token);
    },
    formatError: error => {
        delete error.extensions.exception;
        return error;
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
