/* eslint-disable camelcase */
// noinspection ExceptionCaughtLocallyJS

import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import nconf from 'nconf';
import express from 'express';
import { parse as parseContentType } from 'content-type';
import { findById as findWorkById } from '../domain/work';
import { basePath, getBaseUrl, logApp } from '../config/conf';
import { AuthRequired, error, ForbiddenAccess, UNSUPPORTED_ERROR, UnsupportedError } from '../config/errors';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { findById, restAllCollections, restBuildCollection, restCollectionManifest, restCollectionStix } from '../domain/taxii';
import { executionContext, isUserHasCapability, SYSTEM_USER } from '../utils/access';
import { findById as findTaxiiCollection } from '../modules/ingestion/ingestion-taxii-collection-domain';
import { handleConfidenceToScoreTransformation, pushBundleToConnectorQueue } from '../manager/ingestionManager';
import { now } from '../utils/format';
import { computeWorkStatus } from '../domain/connector';
import { ENTITY_TYPE_INGESTION_TAXII_COLLECTION } from '../modules/ingestion/ingestion-types';
import { TAXIIAPI } from '../domain/user';
import { createAuthenticatedContext } from './httpAuthenticatedContext';

const TAXII_REQUEST_ALLOWED_CONTENT_TYPE = ['application/taxii+json', 'application/vnd.oasis.stix+json'];
const TAXII_VERSION = '2.1';
const TAXII_RESPONSE_CONTENT_TYPE = `application/taxii+json;version=${TAXII_VERSION}`;

const TaxiiError = (message, code) => {
  return error(UNSUPPORTED_ERROR, message, { http_status: code });
};
const sendJsonResponse = (res, data) => {
  res.setHeader('content-type', TAXII_RESPONSE_CONTENT_TYPE);
  res.json(data);
};

const errorConverter = (e) => {
  return {
    title: e.message,
    error_code: e?.extensions?.code,
    http_status: e?.extensions?.data?.http_status || 500,
  };
};

const checkAuthenticationFromRequest = async (req, res) => {
  // noinspection UnnecessaryLocalVariableJS
  const context = await createAuthenticatedContext(req, res, 'taxii');
  if (!context.user) {
    res.setHeader('WWW-Authenticate', 'Basic, Bearer');
    throw AuthRequired();
  }
  if (!isUserHasCapability(context.user, TAXIIAPI)) {
    throw ForbiddenAccess();
  }
  return context;
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

const extractUserAndCollection = async (req, res, id) => {
  const findCollection = await findById(executionContext('taxii'), SYSTEM_USER, id);
  if (!findCollection) {
    throw ForbiddenAccess();
  }
  if (findCollection.taxii_public) {
    return { user: SYSTEM_USER, collection: findCollection };
  }
  const context = await checkAuthenticationFromRequest(req, res);
  const userCollection = await findById(context, context.user, id);
  if (!userCollection) {
    throw TaxiiError('Collection not found', 404);
  }
  return { context, user: context.user, collection: userCollection };
};

const isValidTaxiiPostContentType = (req) => {
  const contentTypeFromRequest = parseContentType(req);
  return (TAXII_REQUEST_ALLOWED_CONTENT_TYPE.includes(contentTypeFromRequest.type) && contentTypeFromRequest.parameters.version === TAXII_VERSION);
};

const JsonTaxiiMiddleware = express.json({
  type: (req) => {
    try {
      return isValidTaxiiPostContentType(req);
    } catch (_e) {
      logApp.info('[Taxii] Content-Type from incoming request is missing or invalid', { contentType: req?.headers['content-type'] });
      return false;
    }
  },
  limit: nconf.get('app:max_payload_body_size') || '50mb'
});

const initTaxiiApi = (app) => {
  // Discovery api
  app.get(`${basePath}/taxii2/`, async (req, res) => {
    try {
      await checkAuthenticationFromRequest(req, res);
      const discovery = {
        title: 'OpenCTI TAXII Server',
        description: 'This TAXII Server exposes OpenCTI data through taxii protocol',
        default: `${getBaseUrl(req)}/taxii2/root/`,
        api_roots: [`${getBaseUrl(req)}/taxii2/root/`],
      };
      sendJsonResponse(res, discovery);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Root api
  app.get(`${basePath}/taxii2/root/`, async (req, res) => {
    try {
      await checkAuthenticationFromRequest(req, res);
      const rootContent = {
        title: 'OpenCTI TAXII Server',
        description: 'A global and natively segregate taxii root',
        max_content_length: 100 * 1024 * 1024, // '100mb'
        versions: [TAXII_RESPONSE_CONTENT_TYPE],
      };
      sendJsonResponse(res, rootContent);
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  // Collection api
  app.get(`${basePath}/taxii2/root/collections/`, async (req, res) => {
    try {
      const context = await checkAuthenticationFromRequest(req, res);
      const collections = await restAllCollections(context, context.user);
      sendJsonResponse(res, { collections });
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/`, async (req, res) => {
    const { id } = req.params;
    try {
      const { collection } = await extractUserAndCollection(req, res, id);
      if (collection.entity_type === ENTITY_TYPE_INGESTION_TAXII_COLLECTION && collection.ingestion_running !== true) {
        throw TaxiiError('Collection not found', 404);
      }
      sendJsonResponse(res, restBuildCollection(collection));
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
  app.get(`${basePath}/taxii2/root/collections/:id/manifest/`, async (req, res) => {
    const { id } = req.params;
    try {
      const { context, user, collection } = await extractUserAndCollection(req, res, id);
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
  app.get(`${basePath}/taxii2/root/collections/:id/objects/`, async (req, res) => {
    const { id } = req.params;
    try {
      const { context, user, collection } = await extractUserAndCollection(req, res, id);
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
  app.get(`${basePath}/taxii2/root/collections/:id/objects/:object_id/`, async (req, res) => {
    const { id, object_id } = req.params;
    try {
      const { context, user, collection } = await extractUserAndCollection(req, res, id);
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
  app.get(`${basePath}/taxii2/root/collections/:id/objects/:object_id/versions/`, async (req, res) => {
    const { id, object_id } = req.params;
    try {
      const { context, user, collection } = await extractUserAndCollection(req, res, id);
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
  app.post(`${basePath}/taxii2/root/collections/:id/objects/`, JsonTaxiiMiddleware, async (req, res) => {
    try {
    // Authentication is checked in this method, keep it first but inside try block.
      const context = await checkAuthenticationFromRequest(req, res);
      if (!isValidTaxiiPostContentType(req)) {
        throw TaxiiError('Content-Type in request is missing or invalid', 400);
      }

      const { id } = req.params;
      const { objects = [] } = req.body;

      if (objects.length === 0) {
        throw UnsupportedError('Objects required');
      }
      // Find and validate the collection
      const ingestion = await findTaxiiCollection(context, context.user, id);
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
  app.get(`${basePath}/taxii2/root/status/:status_id/`, async (req, res) => {
    const { status_id } = req.params;
    try {
      const context = await checkAuthenticationFromRequest(req, res);
      const work = await findWorkById(context, context.user, status_id);
      if (!work) throw UnsupportedError('Work not found', { status_id });
      const stats = await computeWorkStatus(work);
      if (!stats) throw UnsupportedError('Work not found', { status_id });
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
  app.delete(`${basePath}/taxii2/root/collections/:id/objects/:object_id/`, async (_req, res) => {
    const e = UnsupportedError('Unsupported operation');
    const errorDetail = errorConverter(e);
    res.status(errorDetail.http_status).send(errorDetail);
  });
};

export default initTaxiiApi;
