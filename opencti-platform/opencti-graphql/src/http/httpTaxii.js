/* eslint-disable camelcase */
import * as R from 'ramda';
import { authenticateUserFromRequest, TAXIIAPI } from '../domain/user';
import { basePath } from '../config/conf';
import { AuthRequired, ForbiddenAccess, UnsupportedError } from '../config/errors';
import {
  restAllCollections,
  restCollectionManifest,
  restCollectionStix,
  restLoadCollectionById,
} from '../domain/taxii';
import { BYPASS, getBaseUrl } from '../utils/access';

const TAXII_VERSION = 'application/taxii+json;version=2.1';

const errorConverter = (e) => {
  const details = R.pipe(R.dissoc('reason'), R.dissoc('http_status'))(e.data);
  return {
    title: e.message,
    error_code: e.name,
    description: e.data?.reason,
    http_status: e.data?.http_status || 500,
    details,
  };
};
const userHaveAccess = (user) => {
  const capabilities = user.capabilities.map((c) => c.name);
  return capabilities.includes(BYPASS) || capabilities.includes(TAXIIAPI);
};
const extractUserFromRequest = async (req, res) => {
  res.setHeader('content-type', TAXII_VERSION);
  // noinspection UnnecessaryLocalVariableJS
  const user = await authenticateUserFromRequest(req, res);
  if (!user) {
    res.setHeader('WWW-Authenticate', 'Basic, Bearer');
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

const initTaxiiApi = (app) => {
  // Discovery api
  app.get(`${basePath}/taxii2`, async (req, res) => {
    try {
      await extractUserFromRequest(req, res);
      const discovery = {
        title: 'OpenCTI TAXII Server',
        description: 'This TAXII Server exposes OpenCTI data through taxii protocol',
        default: '/root',
        api_roots: [`${getBaseUrl(req)}/taxii2/root`],
      };
      res.json(discovery);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Root api
  app.get(`${basePath}/taxii2/root`, async (req, res) => {
    try {
      await extractUserFromRequest(req, res);
      const rootContent = {
        title: 'OpenCTI TAXII Server',
        description: 'A global and natively segregate taxii root',
        max_content_length: 100 * 1024 * 1024, // '100mb'
        versions: [TAXII_VERSION],
      };
      res.json(rootContent);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Collection api
  app.get(`${basePath}/taxii2/root/collections`, async (req, res) => {
    try {
      const user = await extractUserFromRequest(req, res);
      const collections = await restAllCollections(user);
      res.json({ collections });
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id`, async (req, res) => {
    const { id } = req.params;
    try {
      const user = await extractUserFromRequest(req, res);
      const collection = await restLoadCollectionById(user, id);
      res.json(collection);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/manifest`, async (req, res) => {
    const { id } = req.params;
    try {
      const user = await extractUserFromRequest(req, res);
      const manifest = await restCollectionManifest(user, id, req.query);
      res.set('X-TAXII-Date-Added-First', R.head(manifest.objects)?.updated_at);
      res.set('X-TAXII-Date-Added-Last', R.last(manifest.objects)?.updated_at);
      res.json(manifest);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects`, async (req, res) => {
    const { id } = req.params;
    try {
      const user = await extractUserFromRequest(req, res);
      const stix = await restCollectionStix(user, id, req.query);
      res.set('X-TAXII-Date-Added-First', R.head(stix.objects)?.updated_at);
      res.set('X-TAXII-Date-Added-Last', R.last(stix.objects)?.updated_at);
      res.json(stix);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects/:object_id`, async (req, res) => {
    const { id, object_id } = req.params;
    try {
      const user = await extractUserFromRequest(req, res);
      const args = rebuildParamsForObject(object_id, req);
      const stix = await restCollectionStix(user, id, args);
      res.set('X-TAXII-Date-Added-First', R.head(stix.objects)?.updated_at);
      res.set('X-TAXII-Date-Added-Last', R.last(stix.objects)?.updated_at);
      res.json(stix);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects/:object_id/versions`, async (req, res) => {
    const { id, object_id } = req.params;
    try {
      const user = await extractUserFromRequest(req, res);
      const args = rebuildParamsForObject(object_id, req);
      const stix = await restCollectionStix(user, id, args);
      const data = R.head(stix.objects);
      res.set('X-TAXII-Date-Added-First', data?.updated_at);
      res.set('X-TAXII-Date-Added-Last', data?.updated_at);
      const versions = data ? [data.updated_at] : [];
      res.json({ versions });
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Unsupported api
  app.get(`${basePath}/taxii2/root/status/:status_id`, async (req, res) => {
    const e = UnsupportedError('Unsupported operation');
    const errorDetail = errorConverter(e);
    res.status(errorDetail.http_status).send(errorDetail);
  });
  app.post(`${basePath}/taxii2/root/collections/:id/objects`, async (req, res) => {
    const e = UnsupportedError('Unsupported operation');
    const errorDetail = errorConverter(e);
    res.status(errorDetail.http_status).send(errorDetail);
  });
  app.delete(`${basePath}/taxii2/root/collections/:id/objects/:object_id`, async (req, res) => {
    const e = UnsupportedError('Unsupported operation');
    const errorDetail = errorConverter(e);
    res.status(errorDetail.http_status).send(errorDetail);
  });
};

export default initTaxiiApi;
