import { readFileSync } from 'fs';
import { resolve } from 'path';
import session, { MemoryStore } from 'express-session';
import Keycloak from 'keycloak-connect';

function configureKeycloak(app, graphqlPath) {
  const keycloakConfig = JSON.parse(readFileSync(resolve('./config/keycloak.json')))
  const memoryStore = new MemoryStore()

  app.use(session({
    secret: process.env.SESSION_SECRET_STRING || 'this should be a long secret',
    resave: false,
    saveUninitialized: true,
    store: memoryStore
  }))

  const keycloak = new Keycloak({
    store: memoryStore
  }, keycloakConfig)

  // Install general keycloak middleware
  app.use(keycloak.middleware({
    admin: graphqlPath
  }))

  // Protect the main route for all graphql services
  // Disable unauthenticated access
  app.use(graphqlPath, keycloak.middleware())

  return { keycloak }
}

export default configureKeycloak ;