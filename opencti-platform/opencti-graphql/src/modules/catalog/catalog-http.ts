import type { RequestHandler } from 'express';
import { createAuthenticatedContext } from '../../http/httpAuthenticatedContext';
import { downloadFile } from '../../database/raw-file-storage';
import { logCatalog } from './catalog-logger';
import { logBoundaryError } from '../../config/module-logger';
import { APP_MODULE } from '../../config/error-origin';
import { setCookieError } from '../../http/httpUtils';
import { CATALOG_CONTRACT_LOGOS_DIR, getMimeTypeFromImageExtension } from './catalog-logo-storage';
import { FunctionalError, ResourceNotFoundError, UnknownError } from '../../config/errors';

export const CATALOG_LOGO_VIEW_PATH = '/catalog/logo/*file';

const CONTEXT_SOURCE = 'catalog_logo_view';

export const handleCatalogLogoViewRequest: RequestHandler = async (req, res) => {
  try {
    const context = await createAuthenticatedContext(req, res, CONTEXT_SOURCE);
    if (!context.user) {
      res.sendStatus(403);
      return;
    }
    const fileParam = req.params.file;
    const file = Array.isArray(fileParam) ? fileParam[0] : fileParam;
    logCatalog.debug('Catalog logo view handler', { file });
    if (typeof file !== 'string' || file.includes('..') || file.includes('/') || file.includes('\\')) {
      throw FunctionalError('Invalid URL format');
    }
    const s3Key = `${CATALOG_CONTRACT_LOGOS_DIR}/${file}`;
    const stream = await downloadFile(s3Key);
    if (!stream) {
      const error = ResourceNotFoundError('Catalog logo not found');
      logBoundaryError('Failed to download catalog logo', error, { entryModule: APP_MODULE.CATALOG, file });
      res.status(404).send({ status: 'error', error: error.message });
      return;
    }
    const extension = file.substring(file.lastIndexOf('.'));
    const mimeType = getMimeTypeFromImageExtension(extension);
    res.set({ 'Content-Security-Policy': 'sandbox' });
    res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.set({ Pragma: 'no-cache' });
    if (mimeType) {
      res.set('Content-type', mimeType);
    } else {
      logCatalog.warn('Catalog logo: unable to deduce mimeType from extension', { file, extension });
    }
    stream.pipe(res);
  } catch (exception) {
    const error = exception instanceof Error ? exception : UnknownError('Unknown error');
    setCookieError(res, error.message);
    logBoundaryError('Error viewing catalog logo', error, { entryModule: APP_MODULE.CATALOG });
    res.status(503).send({ status: 'error', error: error.message });
  }
};
