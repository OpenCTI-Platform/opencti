import { describe, expect, it } from 'vitest';
import axios from 'axios';
import { ADMIN_API_TOKEN, API_URI } from '../utils/testQuery';

// A request the platform cannot read is a caller mistake: it must be answered with its own 4xx,
// never with the 500 of the generic error interceptor.
// The info log line is not asserted here: the platform runs in the vitest main process while this
// file runs in a worker, so its logApp instance is not the one this file could spy on.

const BOUNDARY = 'opencti-malformed-request-test';

// Built by hand rather than with FormData: these cases are about the order and the exact shape of
// the parts on the wire, which a FormData implementation is free to normalize.
const multipartBody = (parts: { name: string; value: string; filename?: string }[]) => {
  const body = parts.map(({ name, value, filename }) => {
    const disposition = filename
      ? `form-data; name="${name}"; filename="${filename}"\r\nContent-Type: application/json`
      : `form-data; name="${name}"`;
    return `--${BOUNDARY}\r\nContent-Disposition: ${disposition}\r\n\r\n${value}\r\n`;
  }).join('');
  return `${body}--${BOUNDARY}--\r\n`;
};

const postMultipart = (parts: { name: string; value: string; filename?: string }[], headers: Record<string, string> = {}) => {
  return axios.post(`${API_URI}/graphql`, multipartBody(parts), {
    headers: { 'Content-Type': `multipart/form-data; boundary=${BOUNDARY}`, ...headers },
    validateStatus: () => true,
  });
};

const postRaw = (body: string, contentType: string) => {
  return axios.post(`${API_URI}/graphql`, body, {
    headers: { 'Content-Type': contentType },
    validateStatus: () => true,
  });
};

const UPLOAD_OPERATIONS = JSON.stringify({
  query: 'mutation($file: Upload!) { uploadImport(file: $file) { id } }',
  variables: { file: null },
});
const UPLOAD_FILE = { name: '0', value: '{}', filename: 'upload.json' };

describe('Malformed http request handling', () => {
  describe('Graphql multipart request spec violations', () => {
    it('should answer 400 when the operations field is missing', async () => {
      const response = await postMultipart([{ name: 'foo', value: 'bar' }]);

      expect(response.status).toBe(400);
      expect(response.data?.status).toBe('error');
      expect(response.data?.error).toContain('Missing multipart field');
      expect(response.data?.error).toContain('graphql-multipart-request-spec');
    });

    it('should answer 400 when a file is sent before the map field', async () => {
      const response = await postMultipart([{ name: 'operations', value: UPLOAD_OPERATIONS }, UPLOAD_FILE]);

      expect(response.status).toBe(400);
      expect(response.data?.error).toContain('Misordered multipart fields');
    });

    it('should answer 400 when the operations field is not valid json', async () => {
      const response = await postMultipart([{ name: 'operations', value: '{oops' }]);

      expect(response.status).toBe(400);
      expect(response.data?.error).toContain('Invalid JSON in the');
    });

    it('should answer 400 without relaying a caller supplied map key', async () => {
      // This graphql-upload message interpolates the map entry key, so it must not be relayed.
      const response = await postMultipart([
        { name: 'operations', value: UPLOAD_OPERATIONS },
        { name: 'map', value: '{"<script>":"variables.file"}' },
      ]);

      expect(response.status).toBe(400);
      expect(response.data?.error).toBe('Bad request');
      expect(JSON.stringify(response.data)).not.toContain('<script>');
    });

    it('should let a spec compliant multipart request through', async () => {
      const response = await postMultipart(
        [{ name: 'operations', value: JSON.stringify({ query: '{ __typename }' }) }, { name: 'map', value: '{}' }],
        { Authorization: `Bearer ${ADMIN_API_TOKEN}` },
      );

      expect(response.status).toBe(200);
      expect(response.data?.data?.__typename).toBe('Query');
    });
  });

  describe('Request body parsing', () => {
    it('should answer 400 when the json body cannot be parsed', async () => {
      const response = await postRaw('{"query": ', 'application/json');

      expect(response.status).toBe(400);
      expect(response.data?.status).toBe('error');
      expect(response.data?.error).toBe('Invalid json in request body');
    });

    it('should answer 415 when the charset is not supported', async () => {
      // body-parser only accepts utf-* charsets, so a utf-7 body would pass the gate and be
      // answered by apollo instead of this branch.
      const response = await postRaw('{}', 'application/json; charset=iso-8859-1');

      expect(response.status).toBe(415);
      expect(response.data?.error).toBe('Unsupported charset');
    });
  });

  describe('Path parameter decoding', () => {
    it('should answer 400 without quoting the faulty path back', async () => {
      // Overlong utf-8 encoding of '.', a path traversal probe. The router raises a URIError with a
      // status but no expose flag, so the message must not be returned to the caller.
      const response = await axios.get(`${API_URI}/.env%c0%ae`, { validateStatus: () => true });

      expect(response.status).toBe(400);
      expect(response.data?.status).toBe('error');
      expect(response.data?.error).toBe('Bad request');
      expect(JSON.stringify(response.data)).not.toContain('.env');
    });
  });
});
