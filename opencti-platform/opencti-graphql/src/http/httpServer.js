import https from 'node:https';
import http from 'node:http';
import graphqlUploadExpress from 'graphql-upload/graphqlUploadExpress.mjs';
// eslint-disable-next-line import/extensions
import nconf from 'nconf';
import express from 'express';
import { expressMiddleware } from '@apollo/server/express4';
import { json } from 'body-parser';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { useServer } from 'graphql-ws/lib/use/ws';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';
import passport from 'passport/lib';
import conf, { basePath, booleanConf, loadCert, logApp, PORT } from '../config/conf';
import createApp from './httpPlatform';
import createApolloServer from '../graphql/graphql';
import { isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { applicationSession } from '../database/session';
import { executionContext, isBypassUser, SYSTEM_USER } from '../utils/access';
import { authenticateUserFromRequest, userEditField, userWithOrigin } from '../domain/user';
import { DraftLockedError, ForbiddenAccess } from '../config/errors';
import { getEntitiesMapFromCache, getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { isNotEmptyField } from '../database/utils';
import { DRAFT_STATUS_OPEN } from '../modules/draftWorkspace/draftStatuses';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';

const MIN_20 = 20 * 60 * 1000;
const REQ_TIMEOUT = conf.get('app:request_timeout');
const CERT_KEY_PATH = conf.get('app:https_cert:key');
const CERT_KEY_CERT = conf.get('app:https_cert:crt');
const CA_CERTS = conf.get('app:https_cert:ca');
const rejectUnauthorized = booleanConf('app:https_cert:reject_unauthorized', true);

const createHttpServer = async () => {
  logApp.info('[INIT] Configuring HTTP/HTTPS server');
  const app = express();
  app.use(applicationSession.session);
  app.use(passport.initialize({}));
  const { schema, apolloServer } = createApolloServer();
  let httpServer;
  if (CERT_KEY_PATH && CERT_KEY_CERT) {
    try {
      logApp.info('[INIT] Configuring SSL for HTTPS server.');
      const key = loadCert(CERT_KEY_PATH);
      const cert = loadCert(CERT_KEY_CERT);
      const ca = CA_CERTS.map((path) => loadCert(path));
      const requestCert = isStrategyActivated(STRATEGY_CERT);
      const passphrase = conf.get('app:https_cert:passphrase');
      const options = { key, cert, passphrase, requestCert, rejectUnauthorized, ca };
      httpServer = https.createServer(options, app);
      logApp.info('[INIT] HTTPS server initialization done.');
    } catch (e) {
      logApp.error('[INIT] HTTPS server cannot start, please verify app.https_cert and other configurations', { cause: e });
    }
  } else {
    httpServer = http.createServer(app);
    logApp.info('[INIT] HTTP server initialization done.');
  }
  httpServer.setTimeout(REQ_TIMEOUT || MIN_20);
  // subscriptionServer
  const wsServer = new WebSocketServer({
    server: httpServer,
    path: `${basePath}/graphql`,
  });
  wsServer.on('error', (e) => {
    throw e;
  });
  const serverCleanup = useServer({
    schema,
    context: async (ctx) => {
      const req = ctx.extra.request;
      const webSocket = ctx.extra.socket;
      // This will be run every time the client sends a subscription request
      const wsSession = await new Promise((resolve) => {
        // use same session parser as normal gql queries
        const { session } = applicationSession;
        session(req, {}, () => {
          if (req.session) {
            resolve(req.session);
          }
          return false;
        });
      });
      // We have a good session. attach to context
      if (wsSession?.user) {
        const context = executionContext('api');
        const origin = {
          socket: 'subscription',
          ip: webSocket._socket.remoteAddress,
          user_id: wsSession.user?.id,
          group_ids: wsSession.user?.group_ids,
          organization_ids: wsSession.user?.organizations?.map((o) => o.internal_id) ?? [],
        };
        const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
        const logged = platformUsers.get(wsSession?.user.id);
        context.user = { ...wsSession?.user, ...logged, origin };
        return context;
      }
      throw ForbiddenAccess('User must be authenticated');
    },
  }, wsServer);

  apolloServer.addPlugin(ApolloServerPluginDrainHttpServer({ httpServer }));
  apolloServer.addPlugin({
    async serverWillStart() {
      return {
        async drainServer() {
          await serverCleanup.dispose();
        },
        async renderLandingPage() {
          const html = `
            <!DOCTYPE html>
            <html>
            <head>
              <script>
                location.replace('${basePath}/public/graphql');
              </script>
            </head>
            </html>`;
          return { html };
        },
      };
    },
  });
  await apolloServer.start();
  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '50mb';
  app.use(express.json({ limit: requestSizeLimit }));
  app.use(graphqlUploadExpress());
  app.use(
    `${basePath}/graphql`,
    cors({ origin: basePath }),
    json(),
    expressMiddleware(apolloServer, {
      app,
      path: `${basePath}/graphql`,
      context: async ({ req, res }) => {
        const executeContext = executionContext('api');
        executeContext.req = req;
        executeContext.res = res;
        const settings = await getEntityFromCache(executeContext, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
        executeContext.otp_mandatory = settings?.otp_mandatory ?? false;
        executeContext.workId = req.headers['opencti-work-id']; // Api call comes from a worker processing
        executeContext.draft_context = req.headers['opencti-draft-id']; // Api call is to be made is specific draft context
        executeContext.eventId = req.headers['opencti-event-id']; // Api call is due to listening event
        executeContext.previousStandard = req.headers['previous-standard']; // Previous standard id
        executeContext.synchronizedUpsert = req.headers['synchronized-upsert'] === 'true'; // If full sync needs to be done
        try {
          const user = await authenticateUserFromRequest(executeContext, req);
          if (user) {
            if (!Object.keys(req.headers).some((k) => k === 'opencti-draft-id')) {
              executeContext.draft_context = user.draft_context;
            }
            executeContext.user = userWithOrigin(req, user);
            executeContext.user_otp_validated = true;
            executeContext.user_with_session = isNotEmptyField(req.session?.user);
            if (executeContext.user_with_session) {
              executeContext.user_otp_validated = req.session?.user.otp_validated ?? false;
            }
            if (isBypassUser(executeContext.user)) {
              executeContext.user_inside_platform_organization = true;
            } else {
              const userOrganizationIds = (user.organizations ?? []).map((organization) => organization.internal_id);
              executeContext.user_inside_platform_organization = settings.platform_organization
                ? userOrganizationIds.includes(settings.platform_organization) : true;
            }
          }
        } catch (error) {
          logApp.error('Fail to authenticate the user in graphql context hook', { cause: error });
        }

        // When context is in draft, we need to check draft status: if draft is not in an open status, it means that it is no longer possible to execute requests in this draft
        if (executeContext.draft_context) {
          const draftWorkspaces = await getEntitiesMapFromCache(executeContext, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
          const draftWorkspace = draftWorkspaces.get(executeContext.draft_context);
          if (!draftWorkspace) {
            if (executeContext.user.draft_context === executeContext.draft_context) {
              // If user is stuck in an invalid draft, remove draft context from user
              await userEditField(executeContext, executeContext.user, executeContext.user.id, [{ key: 'draft_context', value: '' }]);
            }
            throw DraftLockedError('Could not find draft workspace');
          }
          if (draftWorkspace.draft_status !== DRAFT_STATUS_OPEN) {
            if (executeContext.user.draft_context === executeContext.draft_context) {
              // If user is stuck in an invalid draft, remove draft context from user
              await userEditField(executeContext, executeContext.user, executeContext.user.id, [{ key: 'draft_context', value: '' }]);
            }
            throw DraftLockedError('Can not execute request in a draft not in an open state');
          }
        }
        return executeContext;
      }
    })
  );
  const { sseMiddleware } = await createApp(app);
  return { httpServer, sseMiddleware };
};

const listenServer = async () => {
  return new Promise((resolve, reject) => {
    try {
      const serverPromise = createHttpServer();
      serverPromise.then(({ httpServer, sseMiddleware }) => {
        httpServer.on('close', () => {
          sseMiddleware.shutdown();
        });
        const server = httpServer.listen(PORT);
        resolve({ server });
      }).catch((reason) => {
        logApp.error('Http listen server error', { cause: reason });
      });
    } catch (e) {
      logApp.error('Http listen server fail', { cause: e });
      reject(e);
    }
  });
};

const stopServer = async ({ server }) => {
  return new Promise((resolve) => {
    server.close(() => {
      resolve();
    });
    server.emit('close'); // force server close
  });
};

const initHttpServer = () => {
  let server;
  return {
    start: async () => {
      server = await listenServer();
    },
    shutdown: async () => {
      if (server) {
        await stopServer(server);
      }
    },
  };
};
const httpServer = initHttpServer();

export default httpServer;
