// A batch of create operations in one request, written with the lock-free path in chunks.
// Each operation is a GraphQL mutation as a client sends it (pycti's create calls, unchanged), executed through the
// platform's own resolvers, so every type keeps its domain rules. Operations run as soon as the operations they
// reference are done, with those references (the client's placeholders) replaced by the real ids. Their creates
// do not write one by one: the collector holds them until every running operation waits on one, then writes them
// as one lock-free chunk, as a DataLoader batches loads.
import { type DocumentNode, execute, type GraphQLSchema, Kind, parse, validate } from 'graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { inferIndexFromConceptType } from '../utils';
import { FunctionalError } from '../../config/errors';
import { mgetRaw, toElements } from './load';
import { newCounters } from './store';
import { type ItemResult, writeEntityChunk, writeRelationChunk } from './writer';

const MAX_CHUNK = 500;
const FLUSHES_AT_ONCE = 4; // chunk writes in flight, as parallel writers

interface Waiting { user: AuthUser; type: string; input: Record<string, any>; resolve: (element: any) => void; reject: (error: unknown) => void }

// The elements as stored, read by id in one realtime get, as createEntity / createRelation return them: without
// the rel_* lists, as today's loads (a busy object lists thousands of ids there), and without the raw document the
// lock-free reads attach (both would go out with every notification of the element)
const storedElements = async (results: ItemResult[], types: string[]) => {
  const refs = results.map((r, i) => (r.id ? { id: r.id, index: inferIndexFromConceptType(types[i]) } : null)).filter(Boolean) as { id: string; index: string }[];
  const raws = await mgetRaw(refs, { light: true });
  const found = await toElements([...raws.values()]);
  found.forEach((e: any) => delete e.i_raw);
  const byId = new Map(found.map((e: any) => [e.internal_id, e]));
  return results.map((r, i) => {
    if (r.status === 'error') return { error: r.cause };
    const element = r.id ? byId.get(r.id) : undefined;
    return element ? { element } : { error: FunctionalError('Lock-free write cannot read its element', { id: r.id, type: types[i] }) };
  });
};

export class WriteCollector {
  private active = 0;

  private flushing = 0;

  private entities: Waiting[] = [];

  private relations: Waiting[] = [];

  constructor(private context: AuthContext) {}

  // An operation starts or resumes running
  enter() {
    this.active += 1;
  }

  // An operation is done or waits on something else than the collector
  exit() {
    this.active -= 1;
    this.maybeFlush();
  }

  private wait(queue: Waiting[], user: AuthUser, type: string, input: Record<string, any>) {
    const promise = new Promise<any>((resolve, reject) => {
      queue.push({ user, type, input, resolve, reject });
    });
    this.exit();
    return promise.finally(() => this.enter());
  }

  createEntity(user: AuthUser, type: string, input: Record<string, any>) {
    return this.wait(this.entities, user, type, input);
  }

  createRelation(user: AuthUser, input: Record<string, any>) {
    return this.wait(this.relations, user, input.relationship_type, input);
  }

  // Writes what waits once every running operation waits on the collector (or a chunk is full), up to
  // FLUSHES_AT_ONCE chunks at a time
  private maybeFlush() {
    while (this.flushing < FLUSHES_AT_ONCE) {
      const queued = this.entities.length + this.relations.length;
      if (queued === 0 || (this.active > 0 && queued < MAX_CHUNK)) return;
      this.flush().catch(() => {});
    }
  }

  private async flush() {
    this.flushing += 1;
    try {
      const entities = this.entities.splice(0, MAX_CHUNK);
      const relations = this.relations.splice(0, MAX_CHUNK);
      await this.write(entities, (user, items) => writeEntityChunk(this.writeContext(), user, items.map((w) => ({ type: w.type, input: w.input })), newCounters(), { missingEnds: 'error' }));
      await this.write(relations, (user, items) => writeRelationChunk(this.writeContext(), user, items.map((w) => w.input), newCounters(), { missingEnds: 'error' }));
    } finally {
      this.flushing -= 1;
    }
    this.maybeFlush();
  }

  private writeContext(): AuthContext {
    return { ...this.context, lockfree_write: true, lockfree_batch: undefined } as AuthContext;
  }

  // Writes the waiting creates, one chunk per user, and settles each one with its element or its error
  private async write(waiting: Waiting[], writeChunk: (user: AuthUser, items: Waiting[]) => Promise<ItemResult[]>) {
    const byUser = new Map<string, Waiting[]>();
    waiting.forEach((w) => {
      const items = byUser.get(w.user.internal_id);
      if (items) items.push(w);
      else byUser.set(w.user.internal_id, [w]);
    });
    for (const items of byUser.values()) {
      try {
        const results = await writeChunk(items[0].user, items);
        const stored = await storedElements(results, items.map((w) => w.type));
        stored.forEach((s, i) => (s.element ? items[i].resolve(s.element) : items[i].reject(s.error)));
      } catch (e) {
        items.forEach((w) => w.reject(e));
      }
    }
  }
}

export interface Operation { ref?: string | null; query: string; variables?: Record<string, any> | null }
export interface OperationResult { status: 'done' | 'error'; id?: string; error?: string; code?: string }

// A batch reads only the id of what an operation created: a create mutation (`...Add`) runs with only `id`
// selected, instead of resolving for nothing the author, markings, labels... of every object it answers (searches
// for each of them). The mutation itself runs the same. Any other shape, or a rewrite the schema refuses, runs as sent.
export const idOnlyDocument = (schema: GraphQLSchema, document: DocumentNode): DocumentNode => {
  const definition: any = document.definitions[0];
  const field = definition?.selectionSet?.selections?.[0];
  if (document.definitions.length !== 1 || definition.selectionSet.selections.length !== 1 || !field?.selectionSet
    || !field.name?.value?.endsWith('Add')) {
    return document;
  }
  const idOnly = { kind: Kind.SELECTION_SET, selections: [{ kind: Kind.FIELD, name: { kind: Kind.NAME, value: 'id' } }] };
  const selectionSet = { ...definition.selectionSet, selections: [{ ...field, selectionSet: idOnly }] };
  const rewritten = { ...document, definitions: [{ ...definition, selectionSet }] } as DocumentNode;
  return validate(schema, rewritten).length === 0 ? rewritten : document;
};

const documents = new Map<string, { document: DocumentNode; field: string } | { invalid: string }>();
const documentOf = (schema: GraphQLSchema, query: string) => {
  let entry = documents.get(query);
  if (!entry) {
    try {
      const document = parse(query);
      const errors = validate(schema, document);
      const definition: any = document.definitions[0];
      const field = definition?.selectionSet?.selections?.[0]?.name?.value;
      if (errors.length > 0 || definition?.operation !== 'mutation' || !field) {
        entry = { invalid: errors[0]?.message ?? 'Only mutations are accepted' };
      } else {
        entry = { document: idOnlyDocument(schema, document), field };
      }
    } catch (e: any) {
      entry = { invalid: e.message };
    }
    if (documents.size > 1000) documents.clear();
    documents.set(query, entry);
  }
  return entry;
};

// Every string in a value, deep
const stringsOf = (value: any, out: Set<string>) => {
  if (typeof value === 'string') out.add(value);
  else if (Array.isArray(value)) value.forEach((v) => stringsOf(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => stringsOf(v, out));
  return out;
};
export const replaceStrings = (value: any, ids: Map<string, string>): any => {
  if (typeof value === 'string') return ids.get(value) ?? value;
  if (Array.isArray(value)) return value.map((v) => replaceStrings(v, ids));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, replaceStrings(v, ids)]));
  return value;
};

// The references of each operation to the others; references closing a cycle are left out
export const dependenciesOf = (operations: Operation[]) => {
  const byRef = new Map<string, number>();
  operations.forEach((op, i) => {
    if (op.ref) byRef.set(op.ref, i);
  });
  const deps = operations.map((op, i) => [...stringsOf(op.variables ?? {}, new Set())]
    .map((s) => byRef.get(s))
    .filter((d): d is number => d !== undefined && d !== i));
  const state = operations.map(() => 0); // 0 unseen, 1 in progress, 2 done
  const visit = (i: number) => {
    state[i] = 1;
    deps[i] = deps[i].filter((d) => {
      if (state[d] === 1) return false; // cycle: run without waiting for it
      if (state[d] === 0) visit(d);
      return true;
    });
    state[i] = 2;
  };
  operations.forEach((_, i) => {
    if (state[i] === 0) visit(i);
  });
  return deps;
};

export const executeOperations = async (context: AuthContext, schema: GraphQLSchema, operations: Operation[]): Promise<OperationResult[]> => {
  const collector = new WriteCollector(context);
  const batchContext = { ...context, lockfree_batch: collector } as AuthContext;
  const deps = dependenciesOf(operations);
  const ids = new Map<string, string>(); // placeholder ref -> real id
  const results: OperationResult[] = operations.map(() => ({ status: 'error' }));
  const done: Promise<void>[] = [];
  const run = async (i: number) => {
    await Promise.all(deps[i].map((d) => done[d]));
    const failedDep = deps[i].find((d) => results[d].status === 'error');
    if (failedDep !== undefined) {
      results[i] = { status: 'error', error: `Referenced object ${operations[failedDep].ref} was not imported`, code: 'MISSING_REFERENCE_ERROR' };
      return;
    }
    const entry = documentOf(schema, operations[i].query);
    if ('invalid' in entry) {
      results[i] = { status: 'error', error: entry.invalid, code: 'GRAPHQL_VALIDATION_FAILED' };
      return;
    }
    collector.enter();
    try {
      const response: any = await execute({ schema, document: entry.document, variableValues: replaceStrings(operations[i].variables ?? {}, ids), contextValue: batchContext });
      if (response.errors?.length > 0) {
        const error = response.errors[0];
        results[i] = { status: 'error', error: error.message, code: error.extensions?.code ?? error.originalError?.name };
      } else {
        const id = response.data?.[entry.field]?.id;
        results[i] = { status: 'done', id };
        if (operations[i].ref && id) ids.set(operations[i].ref as string, id);
      }
    } catch (e: any) {
      results[i] = { status: 'error', error: e?.message ?? String(e), code: e?.extensions?.code ?? e?.name };
    } finally {
      collector.exit();
    }
  };
  // Operations are registered before any of them runs, so that every dependency's promise exists
  const started: (() => Promise<void>)[] = operations.map((_, i) => () => run(i));
  const gates = operations.map(() => {
    let open = () => {};
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    return { gate, open };
  });
  operations.forEach((_, i) => {
    done[i] = gates[i].gate.then(started[i]);
  });
  gates.forEach((g) => g.open());
  await Promise.all(done);
  return results;
};
