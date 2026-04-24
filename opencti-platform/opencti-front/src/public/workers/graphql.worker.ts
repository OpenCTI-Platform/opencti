/**
 * Monaco GraphQL web worker entry point.
 *
 * We call initialize() directly at module-load time instead of relying on the
 * onmessage-wrapper inside "monaco-graphql/esm/graphql.worker.js".
 *
 * In an IIFE classic worker the first message from Monaco's WebWorker is a raw
 * string ('vs/base/common/worker/simpleWorker') that has no `vsWorker` field.
 * When `initialize()` is triggered lazily on *that* first message, a race can
 * occur in production where the SimpleWorkerServer is not yet listening when
 * the real $initialize RPC arrives.  Calling initialize() eagerly avoids the
 * race entirely: globalThis.onmessage is replaced with simpleWorker.onmessage
 * before any message dispatch takes place.
 */
import { initialize } from 'monaco-editor/esm/vs/editor/editor.worker';
import { GraphQLWorker } from 'monaco-graphql/esm/GraphQLWorker';

initialize((ctx, createData) => new GraphQLWorker(ctx, createData));
