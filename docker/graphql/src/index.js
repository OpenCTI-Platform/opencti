// require("dotenv").config();
import express from "express";
import getSchema from "./schema/index.js" ;

import startApolloServer from "./servers/graphql.js";

(async () => {
  const port = process.env.PORT || 4000;
  const app = express();
  const schema = await getSchema();

  startApolloServer( app, port, schema )

  // app.listen({ port }, () => {
  //   console.log(`🚀  Server ready http://localhost:${port}`);
  // });
})();
