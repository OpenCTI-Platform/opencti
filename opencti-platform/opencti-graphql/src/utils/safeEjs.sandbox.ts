import vm from 'node:vm';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import type { Data, Options } from 'ejs';

// A sandbox is a V8 context of its own, with its own intrinsics and its own ejs instance.
// A write on Math, JSON, Array and friends stays inside the sandbox that made it.

export interface EjsSandbox {
  readGlobals: (names: string[]) => Record<string, unknown>;
  runInContext: (code: string) => unknown;
  render: (template: string, data: Data, options: Options) => string | Promise<string>;
}

interface EjsModule {
  render: (template: string, data: Data, options: Options) => string | Promise<string>;
}
type SandboxRequire = (name: string) => unknown;

// The sandbox evaluates ejs from its source, so the source must ship with the bundle: the builder
// copies it next to the bundled files, where no node_modules is available.
const resolveEjsDirectory = () => {
  const isProduction = import.meta.url.endsWith('.mjs');
  return isProduction ? fileURLToPath(new URL('ejs/', import.meta.url)) : path.dirname(createRequire(import.meta.url).resolve('ejs'));
};
const ejsDirectory = resolveEjsDirectory();

const compileModule = (fileName: string) => {
  const source = fs.readFileSync(path.join(ejsDirectory, fileName), 'utf8');
  return new vm.Script(`(function (module, exports, require) {${source}\nreturn module.exports;})`);
};

const EJS_SCRIPTS: Record<string, vm.Script> = {
  ejs: compileModule('ejs.js'),
  './utils.js': compileModule('utils.js'),
};

// ejs only reaches for fs and path to read template files from disk, which never happens here:
// templates arrive as strings. The stubs keep it from touching the real modules.
const NODE_STUBS: Record<string, unknown> = {
  fs: {},
  path: {
    join: (...parts: string[]) => parts.join('/'),
    dirname: (target: string) => target,
    resolve: (...parts: string[]) => parts.join('/'),
    extname: () => '',
  },
};

const loadEjsInSandbox = (context: vm.Context): EjsModule => {
  const loaded: Record<string, unknown> = {};
  const sandboxRequire: SandboxRequire = (name) => {
    if (name in NODE_STUBS) {
      return NODE_STUBS[name];
    }
    if (name in loaded) {
      return loaded[name];
    }
    const script = EJS_SCRIPTS[name];
    if (!script) {
      throw new Error(`Module is not available to templates: ${name}`);
    }
    const module = { exports: {} };
    const factory = script.runInContext(context) as (m: typeof module, e: unknown, r: SandboxRequire) => unknown;
    loaded[name] = factory(module, module.exports, sandboxRequire);
    return loaded[name];
  };
  return sandboxRequire('ejs') as EjsModule;
};

export type ErrorSource = { name?: string; message?: string; stack?: string };
export type RestoreError = (source: ErrorSource) => Error;

// An error raised inside the sandbox belongs to its realm, so `instanceof Error` is false for it
// in the host. Callers rely on that check, so rebuild a host error from it, letting the caller map
// a known error name back to its public type.
const toHostError = (error: unknown, restoreError?: RestoreError): Error => {
  if (error instanceof Error) {
    return error;
  }
  const source = (error ?? {}) as ErrorSource;
  if (restoreError) {
    return restoreError({ name: source.name, message: source.message ?? String(error), stack: source.stack });
  }
  const hostError = new Error(source.message ?? String(error));
  if (source.name) {
    hostError.name = source.name;
  }
  if (source.stack) {
    hostError.stack = source.stack;
  }
  return hostError;
};

export const createEjsSandbox = (sandboxOptions?: { restoreError?: RestoreError }): EjsSandbox => {
  const context = vm.createContext({});
  const ejsInSandbox = loadEjsInSandbox(context);
  const restoreError = sandboxOptions?.restoreError;
  return {
    // The globals handed to a template must be the sandbox's own, never the host's.
    readGlobals: (names) => vm.runInContext(`({${names.map((name) => `${JSON.stringify(name)}:${name}`).join(',')}})`, context),
    // Lets the caller build sandbox-realm values (a data clone, the guards) so nothing a template
    // reaches inherits from the host realm's shared prototypes.
    runInContext: (code) => vm.runInContext(code, context),
    render: (template, data, options) => {
      // Coerce the output to a primitive string inside the sandbox: a template can return a thenable,
      // and handing it to a host await/.then/.catch would pass it a host-realm callback (its `.call`
      // then exposes the shared Function prototype). String() only invokes the value's own toString,
      // never a callback. A real async render goes through ejs's own sandbox-realm promise.
      const asString = (result: unknown): string => (typeof result === 'string' ? result : String(result));
      try {
        const rendered = ejsInSandbox.render(template, data, options);
        if (options.async) {
          // The .catch covers both a rejected render and a sandbox error thrown while stringifying.
          return Promise.resolve(rendered).then((result) => asString(result)).catch((error: unknown) => {
            throw toHostError(error, restoreError);
          });
        }
        return asString(rendered);
      } catch (error) {
        throw toHostError(error, restoreError);
      }
    },
  };
};
