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

// An error raised inside the sandbox belongs to its realm, so `instanceof Error` is false for it
// in the host. Callers rely on that check, so rebuild a host error from it.
const toHostError = (error: unknown): Error => {
  if (error instanceof Error) {
    return error;
  }
  const source = error as { name?: string; message?: string; stack?: string } | null;
  const hostError = new Error(source?.message ?? String(error));
  if (source?.name) {
    hostError.name = source.name;
  }
  if (source?.stack) {
    hostError.stack = source.stack;
  }
  return hostError;
};

const isThenable = (value: unknown): value is Promise<string> => {
  return typeof (value as { then?: unknown } | null)?.then === 'function';
};

export const createEjsSandbox = (): EjsSandbox => {
  const context = vm.createContext({});
  const ejsInSandbox = loadEjsInSandbox(context);
  return {
    // The globals handed to a template must be the sandbox's own, never the host's.
    readGlobals: (names) => vm.runInContext(`({${names.map((name) => `${JSON.stringify(name)}:${name}`).join(',')}})`, context),
    render: (template, data, options) => {
      try {
        const rendered = ejsInSandbox.render(template, data, options);
        if (isThenable(rendered)) {
          return rendered.catch((error: unknown) => {
            throw toHostError(error);
          });
        }
        return rendered;
      } catch (error) {
        throw toHostError(error);
      }
    },
  };
};
