import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { createGunzip, gzip as gzipCallback } from 'node:zlib';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import nconf from 'nconf';
import { basePath, logApp } from '../config/conf';
import { memoize } from '../utils/memoize';
import { downloadFile, downloadFileRange, downloadLocalFileRange, getFileMetadata } from '../database/raw-file-storage';

const gzip = promisify(gzipCallback);

export const MAP_CUSTOM_FILE_KEY = 'maps/world.pmtiles';
export const COUNTRIES_CUSTOM_FILE_KEY = 'maps/countries.json.gz';

// Tile data is already compressed inside the PMTiles container, so re-encoding it on the way
// out costs CPU for nothing: gzipping the bundled file measures at -0.01% on the whole file
// and 0.10% on a 16 KB slice. no-transform keeps both the compression middleware and any
// intermediary from doing it.
const TILES_CACHE_CONTROL = 'public, max-age=86400, no-transform';
const COUNTRIES_CACHE_CONTROL = 'public, max-age=86400';

const initHttpMaps = (app, {
  tilesPath = nconf.get('app:map_bundled_file_path'),
  countriesPath = nconf.get('app:map_countries_bundled_file_path'),
} = {}) => {
  // -- Map tiles, with Range request support
  app.get(`${basePath}/maps/world.pmtiles`, async (req, res) => {
    try {
      // Map file contains no sensitive data and must remain reachable from public dashboards
      // and export contexts where no authenticated session is available.
      const rangeHeader = req.headers.range;

      // The custom (S3-backed) file always takes priority when present; otherwise fall
      // back to the bundled file. There is no separate "mode" setting to keep in sync.
      const customResult = await downloadFileRange(MAP_CUSTOM_FILE_KEY, rangeHeader);
      const usedCustom = !!customResult;
      const result = customResult ?? await downloadLocalFileRange(tilesPath, rangeHeader);

      if (!result) {
        res.sendStatus(404);
        return;
      }

      if (result.rangeNotSatisfiable) {
        res.set('Content-Range', `bytes */${result.totalSize}`);
        res.sendStatus(416);
        return;
      }

      // Set before the revalidation check so a 304 carries the same validator as the 200 it
      // replaces; otherwise the client stores whatever express derives from the empty body and
      // never gets a cache hit again.
      const etag = result.etag ?? `"${usedCustom ? 'custom' : 'bundled'}-${result.totalSize}"`;
      res.set('ETag', etag);
      const ifNoneMatch = req.headers['if-none-match'];
      if (ifNoneMatch && ifNoneMatch === etag) {
        result.stream.destroy();
        res.sendStatus(304);
        return;
      }

      res.set('Content-Type', 'application/octet-stream');
      res.set('Accept-Ranges', 'bytes');
      res.set('Cache-Control', TILES_CACHE_CONTROL);
      res.set('Access-Control-Expose-Headers', 'Content-Range, Content-Length, ETag');
      if (result.contentRange) {
        res.status(206);
        res.set('Content-Range', result.contentRange);
        res.set('Content-Length', result.contentLength);
      } else {
        res.status(200);
        res.set('Content-Length', result.totalSize);
      }
      result.stream.pipe(res);
    } catch (e) {
      logApp.error('Error serving map file', { cause: e });
      if (!res.headersSent) {
        res.status(503).send({ status: 'error', error: e.message });
      } else {
        res.destroy(e);
      }
    }
  });

  // -- Country boundaries, always stored and served gzipped
  const getBundledCountries = memoize(async () => {
    const gzipped = await gzip(await readFile(countriesPath));
    const digest = createHash('sha256').update(gzipped).digest('hex').slice(0, 32);
    return { gzipped, etag: `"bundled-${digest}"` };
  });
  app.get(`${basePath}/maps/countries.json`, async (req, res) => {
    try {
      // Countries file contains no sensitive data and must remain reachable from public dashboards
      // and export contexts where no authenticated session is available.
      const customMeta = await getFileMetadata(COUNTRIES_CUSTOM_FILE_KEY);
      // The ETag must follow the content, not its length: two different files can compress
      // to the same number of bytes and would then be served from a stale cache for a day.
      const etag = customMeta
        ? (customMeta.etag ?? `"custom-${customMeta.contentLength}"`)
        : (await getBundledCountries()).etag;

      // The body varies on Accept-Encoding, so a shared cache must not serve the gzipped
      // representation to a client that did not advertise gzip.
      res.set('Vary', 'Accept-Encoding');
      res.set('ETag', etag);
      if (req.headers['if-none-match'] === etag) {
        res.sendStatus(304);
        return;
      }

      const customStream = customMeta ? await downloadFile(COUNTRIES_CUSTOM_FILE_KEY) : null;
      const source = customStream ?? Readable.from([(await getBundledCountries()).gzipped]);

      // Negotiated through express rather than by substring: it honours q values, so a client
      // sending `gzip;q=0` gets the plain body, and `*` gets the compressed one.
      const acceptsGzip = req.acceptsEncodings('gzip') === 'gzip';
      if (acceptsGzip) {
        res.set('Content-Encoding', 'gzip');
      }
      res.set('Content-Type', 'application/json');
      res.set('Cache-Control', COUNTRIES_CACHE_CONTROL);
      res.status(200);
      await (acceptsGzip ? pipeline(source, res) : pipeline(source, createGunzip(), res));
    } catch (e) {
      logApp.error('Error serving countries file', { cause: e });
      if (!res.headersSent) {
        res.status(503).send({ status: 'error', error: e.message });
      } else {
        res.destroy(e);
      }
    }
  });
};

export default initHttpMaps;
