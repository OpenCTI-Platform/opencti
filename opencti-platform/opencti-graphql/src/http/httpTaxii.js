/* eslint-disable camelcase */
// noinspection ExceptionCaughtLocallyJS

import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import nconf from 'nconf';
import express from 'express';
import { authenticateUserFromRequest, TAXIIAPI } from '../domain/user';
import { findById as findWorkById } from '../domain/work';
import { basePath, getBaseUrl } from '../config/conf';
import { AuthRequired, error, ForbiddenAccess, UNSUPPORTED_ERROR, UnsupportedError } from '../config/errors';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { findById, restAllCollections, restBuildCollection, restCollectionManifest, restCollectionStix } from '../domain/taxii';
import { executionContext, isUserHasCapability, SYSTEM_USER } from '../utils/access';
import { findById as findTaxiiCollection } from '../modules/ingestion/ingestion-taxii-collection-domain';
import { handleConfidenceToScoreTransformation, pushBundleToConnectorQueue } from '../manager/ingestionManager';
import { now } from '../utils/format';
import { computeWorkStatus } from '../domain/connector';
import { ENTITY_TYPE_INGESTION_TAXII_COLLECTION } from '../modules/ingestion/ingestion-types';

const TAXII_VERSION = 'application/taxii+json;version=2.1';

const TaxiiError = (message, code) => {
  return error(UNSUPPORTED_ERROR, message, { http_status: code });
};
const sendJsonResponse = (res, data) => {
  res.setHeader('content-type', TAXII_VERSION);
  res.json(data);
};

const errorConverter = (e) => {
  return {
    title: e.message,
    error_code: e.extensions.code,
    http_status: e.extensions.data?.http_status || 500,
  };
};

const extractUserFromRequest = async (context, req, res) => {
  // noinspection UnnecessaryLocalVariableJS
  const user = await authenticateUserFromRequest(context, req, res);
  if (!user) {
    res.setHeader('WWW-Authenticate', 'Basic, Bearer');
    throw AuthRequired();
  }
  if (!isUserHasCapability(user, TAXIIAPI)) throw ForbiddenAccess();
  return user;
};
const rebuildParamsForObject = (id, req) => {
  // Rebuild options
  const { added_after, limit, next, match = {} } = req.query;
  const { spec_version, version } = match;
  const argsMatch = { id, spec_version, version };
  return { added_after, limit, next, match: argsMatch };
};
const getUpdatedAt = (obj) => {
  return obj?.extensions?.[STIX_EXT_OCTI]?.updated_at;
};

const extractUserAndCollection = async (context, req, res, id) => {
  const findCollection = await findById(context, SYSTEM_USER, id);
  if (!findCollection) {
    throw ForbiddenAccess();
  }
  if (findCollection.taxii_public) {
    return { user: SYSTEM_USER, collection: findCollection };
  }
  const authUser = await extractUserFromRequest(context, req, res);
  const userCollection = await findById(context, authUser, id);
  if (!userCollection) {
    throw TaxiiError('Collection not found', 404);
  }
  return { user: authUser, collection: userCollection };
};

const JsonTaxiiMiddleware = express.json({
  type: (req) => {
    return req.headers['content-type'] === TAXII_VERSION;
  },
  limit: nconf.get('app:max_payload_body_size') || '50mb'
});

const initTaxiiApi = (app) => {
  // Discovery api
  app.get(`${basePath}/taxii2`, async (req, res) => {
    try {
      const context = executionContext('taxii');
      await extractUserFromRequest(context, req, res);
      const discovery = {
        title: 'OpenCTI TAXII Server',
        description: 'This TAXII Server exposes OpenCTI data through taxii protocol',
        default: `${getBaseUrl(req)}/taxii2/root`,
        api_roots: [`${getBaseUrl(req)}/taxii2/root`],
      };
      sendJsonResponse(res, discovery);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Root api
  app.get(`${basePath}/taxii2/root`, async (req, res) => {
    try {
      const context = executionContext('taxii');
      await extractUserFromRequest(context, req, res);
      const rootContent = {
        title: 'OpenCTI TAXII Server',
        description: 'A global and natively segregate taxii root',
        max_content_length: 100 * 1024 * 1024, // '100mb'
        versions: [TAXII_VERSION],
      };
      sendJsonResponse(res, rootContent);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Collection api
  app.get(`${basePath}/taxii2/root/collections`, async (req, res) => {
    try {
      const context = executionContext('taxii');
      const user = await extractUserFromRequest(context, req, res);
      const collections = await restAllCollections(context, user);
      sendJsonResponse(res, { collections });
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id`, async (req, res) => {
    const { id } = req.params;
    try {
      const context = executionContext('taxii');
      const { collection } = await extractUserAndCollection(context, req, res, id);
      if (collection.entity_type === ENTITY_TYPE_INGESTION_TAXII_COLLECTION && collection.ingestion_running !== true) {
        throw TaxiiError('Collection not found', 404);
      }
      sendJsonResponse(res, restBuildCollection(collection));
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/manifest`, async (req, res) => {
    const { id } = req.params;
    try {
      const context = executionContext('taxii');
      const { user, collection } = await extractUserAndCollection(context, req, res, id);
      if (collection.entity_type === ENTITY_TYPE_INGESTION_TAXII_COLLECTION) {
        throw TaxiiError('The client does not have access to this manifest resource', 403);
      }
      const manifest = await restCollectionManifest(context, user, collection, req.query);
      if (manifest.objects.length > 0) {
        res.set('X-TAXII-Date-Added-First', R.head(manifest.objects)?.version);
        res.set('X-TAXII-Date-Added-Last', R.last(manifest.objects)?.version);
      }
      sendJsonResponse(res, manifest);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects`, async (req, res) => {
    const { id } = req.params;
    try {
      const context = executionContext('taxii');
      const { user, collection } = await extractUserAndCollection(context, req, res, id);
      if (collection.entity_type === ENTITY_TYPE_INGESTION_TAXII_COLLECTION) {
        throw TaxiiError('The client does not have access to this objects resource', 403);
      }
      const stix = await restCollectionStix(context, user, collection, req.query);
      if (stix.objects.length > 0) {
        res.set('X-TAXII-Date-Added-First', getUpdatedAt(R.head(stix.objects)));
        res.set('X-TAXII-Date-Added-Last', getUpdatedAt(R.last(stix.objects)));
      }
      sendJsonResponse(res, stix);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects/:object_id`, async (req, res) => {
    const { id, object_id } = req.params;
    try {
      const context = executionContext('taxii');
      const { user, collection } = await extractUserAndCollection(context, req, res, id);
      if (collection.entity_type === ENTITY_TYPE_INGESTION_TAXII_COLLECTION) {
        throw TaxiiError('The client does not have access to this objects resource', 403);
      }
      const args = rebuildParamsForObject(object_id, req);
      const stix = await restCollectionStix(context, user, collection, args);
      if (stix.objects.length > 0) {
        res.set('X-TAXII-Date-Added-First', getUpdatedAt(R.head(stix.objects)));
        res.set('X-TAXII-Date-Added-Last', getUpdatedAt(R.last(stix.objects)));
      }
      sendJsonResponse(res, stix);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/objects/:object_id/versions`, async (req, res) => {
    const { id, object_id } = req.params;
    try {
      const context = executionContext('taxii');
      const { user, collection } = await extractUserAndCollection(context, req, res, id);
      if (collection.entity_type === ENTITY_TYPE_INGESTION_TAXII_COLLECTION) {
        throw TaxiiError('The client does not have access to this objects resource', 403);
      }
      const args = rebuildParamsForObject(object_id, req);
      const stix = await restCollectionStix(context, user, collection, args);
      const data = R.head(stix.objects);
      const updatedAt = getUpdatedAt(data);
      res.set('X-TAXII-Date-Added-First', updatedAt);
      res.set('X-TAXII-Date-Added-Last', updatedAt);
      const versions = data ? [updatedAt] : [];
      sendJsonResponse(res, { versions });
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.post(`${basePath}/taxii2/root/collections/:id/objects`, JsonTaxiiMiddleware, async (req, res) => {
    const { id } = req.params;
    const { objects = [] } = req.body;
    try {
      if (objects.length === 0) {
        throw UnsupportedError('Objects required');
      }
      const context = executionContext('taxii');
      const user = await extractUserFromRequest(context, req, res);
      // Find and validate the collection
      const ingestion = await findTaxiiCollection(context, user, id);
      if (!ingestion) {
        throw TaxiiError('Collection not found', 404);
      }
      if (ingestion.ingestion_running !== true) {
        throw TaxiiError('Collection not found', 404);
      }
      const stixObjects = handleConfidenceToScoreTransformation(ingestion, objects);
      // Push the bundle in queue, return the job id
      const bundle = { type: 'bundle', spec_version: '2.1', id: `bundle--${uuidv4()}`, objects: stixObjects };
      // Push the bundle to absorption queue
      const workId = await pushBundleToConnectorQueue(context, ingestion, bundle);
      sendJsonResponse(res, {
        id: workId,
        status: 'pending',
        request_timestamp: now(),
        total_count: objects.length,
        success_count: 0,
        failure_count: 0,
        pending_count: objects.length
      });
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Status api
  app.get(`${basePath}/taxii2/root/status/:status_id`, async (req, res) => {
    const { status_id } = req.params;
    try {
      const context = executionContext('taxii');
      const user = await extractUserFromRequest(context, req, res);
      const work = await findWorkById(context, user, status_id);
      if (!work) throw UnsupportedError('Work not found');
      const stats = await computeWorkStatus(work);
      if (!stats) throw UnsupportedError('Work not found');
      const failure_count = (work.errors ?? []).length;
      const total_count = parseInt(stats.import_expected_number, 10);
      const processed_number = stats.import_processed_number ? parseInt(stats.import_processed_number, 10) : 0;
      const success_count = processed_number - failure_count;
      const pending_count = total_count - processed_number;
      sendJsonResponse(res, {
        id: status_id,
        status: work.status === 'complete' ? 'complete' : 'pending',
        request_timestamp: work.created_at,
        total_count,
        success_count,
        failure_count,
        pending_count
      });
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Unsupported api (delete)
  app.delete(`${basePath}/taxii2/root/collections/:id/objects/:object_id`, async (_req, res) => {
    const e = UnsupportedError('Unsupported operation');
    const errorDetail = errorConverter(e);
    res.status(errorDetail.http_status).send(errorDetail);
  });
};

export default initTaxiiApi;
