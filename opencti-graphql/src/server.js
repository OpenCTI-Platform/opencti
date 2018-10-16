import express from 'express';
import graphqlHTTP from 'express-graphql';
import schema from './schema/schema';
import bodyParser from 'body-parser';
import {driver} from './database/index';
import {createTerminus} from '@godaddy/terminus';
import {login} from "./domain/user";
import jwtMiddleware from 'express-jwt';
import conf from './conf';

// Global variable
//CREATE (user:User {id:'456-456421', username:"jri", password: 'niania', roles: ['ROLE_ADMIN', 'ROLE_USER']})
//CREATE CONSTRAINT ON (user:User) ASSERT user.id IS UNIQUE
const devMode = process.env.NODE_ENV === 'development';
function devMiddleware(req, res, next) {
    req.headers.authorization = 'Bearer ' + conf.get('jwt:dev_token');
    next();
}

let app = express();
if (devMode) app.use(devMiddleware);
app.use('/graphql',
    jwtMiddleware({secret: conf.get('jwt:secret')}),
    graphqlHTTP({
        schema: schema,
        graphiql: devMode,
    })
);

// Handling authorization error smoothly
app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
        res.status(401).send('invalid token...');
    }
});

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
let server = app.listen(conf.get('app:port'));
createTerminus(server, options);
console.log('Running openCTI GraphQL API server at localhost:4000/graphql');