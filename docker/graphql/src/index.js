import express from "express";
import startApolloServer from "./servers/graphql.js";

(async () => {
  const port = process.env.PORT || 4000;
  const app = express();

  startApolloServer( app, port )

})();
