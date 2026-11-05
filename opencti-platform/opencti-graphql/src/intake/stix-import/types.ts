// STIX import: the transformation of STIX objects into GraphQL operations, ported from the
// client library's importer (client-python pycti/utils/opencti_stix2.py and pycti/entities).
// Conventions of the port: `undefined` stands for a value the source never provided (dropped
// from the variables), `null` for an explicit empty value (sent as null), as pycti does with
// its NOT_PROVIDED sentinel and None.

export type StixObject = Record<string, any>;

// A file sent with an operation (GraphQL multipart upload)
export class UploadFile {
  constructor(readonly name: string, readonly data: Buffer, readonly mime: string) {}
}

// Executes one GraphQL operation and returns its `data`; throws on a GraphQL error.
export interface ImportClient {
  query: (document: string, variables?: Record<string, unknown>) => Promise<any>;
}

// The logs of the transformation. `error` carries pycti's per-object error logs (app_logger.error:
// a missing parameter, an object or a value skipped), compared with pycti's goldens; they do not
// fail the object, so a runtime adapter must map them to a warn level. `warn` carries pycti's
// warnings. The meta (object id, cause) is not compared.
export interface ImportLogger {
  error: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
}

// A GraphQL error answered by the platform to one operation (pycti's query raises ValueError)
export class ImportClientError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'ImportClientError';
  }
}

// Python error names pycti raises on an object (binascii.Error, a ValueError, is named Error)
export type PythonErrorName = 'ValueError' | 'TypeError' | 'KeyError' | 'IndexError' | 'AttributeError' | 'Error';

// Error of the transformation of one object. It carries the name of the Python error pycti raises
// at the same point, because that name is the per-object outcome compared with pycti's goldens; it
// is not built with the src/config/errors.js factories, whose names are the platform's error codes
// (an outcome of the transformation, not an API error).
export class StixImportError extends Error {
  constructor(name: PythonErrorName, message: string, readonly data?: Record<string, unknown>) {
    super(message);
    this.name = name;
  }
}
