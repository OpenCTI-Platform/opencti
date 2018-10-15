import express from 'express';
import graphqlHTTP from 'express-graphql';
import {buildSchema} from 'graphql';

let schema = buildSchema(`
  type Query {
    ip: String
  }
`);

function loggingMiddleware(req, res, next) {
    console.log('ip:', req.ip);
    next();
}

let root = {
    ip: function (args, request) {
        return request.ip;
    }
};

let app = express();
app.use(loggingMiddleware);
app.use('/graphql', graphqlHTTP({
    schema: schema,
    rootValue: root,
    graphiql: true,
}));
app.listen(4000);
console.log('Running a GraphQL API server at localhost:4000/graphql');