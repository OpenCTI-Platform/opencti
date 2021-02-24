/* eslint-disable camelcase */
import * as R from 'ramda';
import { BYPASS } from './schema/general';
import { authentication, TAXIIAPI } from './domain/user';
import { OPENCTI_TOKEN } from './config/conf';
import { AuthRequired, ForbiddenAccess, UnsupportedError } from './config/errors';
import { restAllCollections, restCollectionManifest, restCollectionStix, restLoadCollectionById } from './domain/taxii';
import { extractTokenFromBearer } from './graphql/graphql';

const TAXII_VERSION = 'application/taxii+json;version=2.1';

const errorConverter = (e) => {
  const details = R.pipe(R.dissoc('reason'), R.dissoc('http_status'))(e.data);
  return {
    title: e.message,
    description: e.data.reason,
    error_code: e.name,
    http_status: e.data.http_status,
    details,
  };
};
const userHaveAccess = (user) => {
  const capabilities = user.capabilities.map((c) => c.name);
  return capabilities.includes(BYPASS) || capabilities.includes(TAXIIAPI);
};
const extractUser = async (req, res) => {
  res.setHeader('content-type', TAXII_VERSION);
  let token = req.cookies ? req.cookies[OPENCTI_TOKEN] : null;
  token = token || extractTokenFromBearer(req.headers.authorization);
  // noinspection UnnecessaryLocalVariableJS
  const user = await authentication(token);
  if (!user) {
    res.setHeader('WWW-Authenticate', 'Bearer, Cookie');
    throw AuthRequired();
  }
  if (!userHaveAccess(user)) throw ForbiddenAccess();
  return user;
};
const rebuildParamsForObject = (id, req) => {
  // Rebuild options
  const { added_after, limit, next, match = {} } = req.query;
  const { spec_version, version } = match;
  const argsMatch = { id, spec_version, version };
  return { added_after, limit, next, match: argsMatch };
};

const initTaxiiApi = (basePath, app) => {
  // Discovery api
  app.get(`${basePath}/taxii2`, async (req, res) => {
    try {
      await extractUser(req, res);
      const discovery = {
        title: 'OpenCTI TAXII Server',
        description: 'This TAXII Server exposes OpenCTI data through taxii protocol',
        default: `/root`,
        api_roots: [`/root`],
      };
      res.json(discovery);
    } catch (e) {
      const error = errorConverter(e);
      res.status(error.http_status).send(error);
    }
  });
  // Root api
  app.get(`${basePath}/taxii2/root`, async (req, res) => {
    try {
      await extractUser(req, res);
      const rootContent = {
        display_name: 'Taxii OpenCTI root',
        description: 'A global and natively segregate taxii root',
        max_content_length: 100 * 1024 * 1024, // '100mb'
        versions: [TAXII_VERSION],
      };
      res.json(rootContent);
    } catch (e) {
      const error = errorConverter(e);
      res.status(error.http_status).send(error);
    }
  });
  // Collection api
  app.get(`${basePath}/taxii2/root/collections`, async (req, res) => {
    try {
      const user = await extractUser(req, res);
      const collections = await restAllCollections(user);
      res.json({ collections });
    } catch (e) {
      const error = errorConverter(e);
      res.status(error.http_status).send(error);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id`, async (req, res) => {
    const { id } = req.params;
    try {
      const user = await extractUser(req, res);
      const collection = await restLoadCollectionById(user, id);
      res.json(collection);
    } catch (e) {
      const error = errorConverter(e);
      res.status(error.http_status).send(error);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/manifest`, async (req, res) => {
    const { id } = req.params;
    try {
      const user = await extractUser(req, res);
      const manifest = await restCollectionManifest(user, id, req.query);
      res.set('X-TAXII-Date-Added-First', R.head(manifest.objects)?.updated_at);
      res.set('X-TAXII-Date-Added-Last', R.last(manifest.objects)?.updated_at);
      res.json(manifest);
    } catch (e) {
      const error = errorConverter(e);
      res.status(error.http_status).send(error);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects`, async (req, res) => {
    const { id } = req.params;
    try {
      const user = await extractUser(req, res);
      const stix = await restCollectionStix(user, id, req.query);
      res.set('X-TAXII-Date-Added-First', R.head(stix.objects)?.updated_at);
      res.set('X-TAXII-Date-Added-Last', R.last(stix.objects)?.updated_at);
      res.json(stix);
    } catch (e) {
      const error = errorConverter(e);
      res.status(error.http_status).send(error);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects/:object_id`, async (req, res) => {
    const { id, object_id } = req.params;
    try {
      const user = await extractUser(req, res);
      const args = rebuildParamsForObject(object_id, req);
      const stix = await restCollectionStix(user, id, args);
      res.set('X-TAXII-Date-Added-First', R.head(stix.objects)?.updated_at);
      res.set('X-TAXII-Date-Added-Last', R.last(stix.objects)?.updated_at);
      res.json(stix);
    } catch (e) {
      const error = errorConverter(e);
      res.status(error.http_status).send(error);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects/:object_id/versions`, async (req, res) => {
    const { id, object_id } = req.params;
    try {
      const user = await extractUser(req, res);
      const args = rebuildParamsForObject(object_id, req);
      const stix = await restCollectionStix(user, id, args);
      const data = R.head(stix.objects);
      res.set('X-TAXII-Date-Added-First', data?.updated_at);
      res.set('X-TAXII-Date-Added-Last', data?.updated_at);
      const versions = data ? [data.updated_at] : [];
      res.json({ versions });
    } catch (e) {
      const error = errorConverter(e);
      res.status(error.http_status).send(error);
    }
  });
  // Unsupported api
  app.get(`${basePath}/taxii2/root/status/:status_id`, async (req, res) => {
    const error = UnsupportedError('Unsupported operation');
    res.status(error.http_status).send(error);
  });
  app.post(`${basePath}/taxii2/root/collections/:id/objects`, async (req, res) => {
    const error = UnsupportedError('Unsupported operation');
    res.status(error.http_status).send(error);
  });
  app.delete(`${basePath}/taxii2/root/collections/:id/objects/:object_id`, async (req, res) => {
    const error = UnsupportedError('Unsupported operation');
    res.status(error.http_status).send(error);
  });
};

export default initTaxiiApi;
