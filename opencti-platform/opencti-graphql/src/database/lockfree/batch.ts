// A batch of create operations in one request, written with the lock-free path in chunks.
// Each operation is a GraphQL mutation as a client sends it (pycti's create calls, unchanged), executed through the
// platform's own resolvers, so every type keeps its domain rules. Operations run as soon as the operations they
// reference are done, with those references (the client's placeholders) replaced by the real ids. Their creates
// do not write one by one: the collector holds them until every running operation waits on one, then writes them
// as one lock-free chunk, as a DataLoader batches loads.
import * as R from 'ramda';
import { type DocumentNode, execute, type GraphQLSchema, Kind, parse, validate } from 'graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { inferIndexFromConceptType } from '../utils';
import { getInstanceIds } from '../../schema/identifier';
import { FunctionalError } from '../../config/errors';
import { mgetRaw, toElements } from './load';
import { newCounters } from './store';
import { type ItemResult, writeEntityChunk, writeRelationChunk } from './writer';

const MAX_CHUNK = 500;
const FLUSHES_AT_ONCE = 4; // chunk writes in flight, as parallel writers

// A create held by the collector until its chunk is written; settled with the stored element or the error
interface PendingCreate { user: AuthUser; type: string; input: Record<string, any>; resolve: (element: any) => void; reject: (error: unknown) => void }

// The elements as createEntity / createRelation return them: the one the write holds, as today, or else (a merge known
// to change nothing reads nothing) the stored one, read by id in one realtime get. Without the rel_* lists, as today's
// loads (a busy object lists thousands of ids there), and without the raw document the lock-free reads attach (both
// would go out with every notification of the element)
export const withoutListsAndRaw = (element: Record<string, any>) => R.pickBy((_, key: string) => !key.startsWith('rel_') && key !== 'i_raw', element);
const storedElements = async (results: ItemResult[], types: string[]) => {
  const refs = results.flatMap((result, i) => (result.id && !result.element ? [{ id: result.id, index: inferIndexFromConceptType(types[i]) }] : []));
  const raws = await mgetRaw(refs, { light: true });
  const found = await toElements([...raws.values()]);
  found.forEach((element) => delete element.i_raw);
  const byId = new Map(found.map((element) => [element.internal_id, element]));
  return results.map((result, i) => {
    if (result.status === 'error') return { error: result.cause };
    const element = result.element ? withoutListsAndRaw(result.element) : byId.get(result.id ?? '');
    if (element) return { element };
    return { error: FunctionalError('Lock-free write cannot read its element', { id: result.id, type: types[i] }) };
  });
};

export class WriteCollector {
  private active = 0; // operations running, not waiting on the collector

  private flushing = 0; // chunk writes in flight

  private entities: PendingCreate[] = [];

  private relations: PendingCreate[] = [];

  // Elements the request read, by lowercased id, shared by its finders (each chunk's, and a domain's that resolves refs
  // before creating): the refs most objects share (markings, author, external references) are read once per request.
  // Whatever the request writes is dropped from it, so that nothing reads an older version than the request wrote.
  readRefs = new Map<string, any>();

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

  createEntity(user: AuthUser, type: string, input: Record<string, any>) {
    return this.hold(this.entities, user, type, input);
  }

  createRelation(user: AuthUser, input: Record<string, any>) {
    return this.hold(this.relations, user, input.relationship_type, input);
  }

  // Holds a create for the next chunk: its operation waits on the collector until the chunk is written
  private hold(queue: PendingCreate[], user: AuthUser, type: string, input: Record<string, any>) {
    const written = new Promise<any>((resolve, reject) => {
      queue.push({ user, type, input, resolve, reject });
    });
    this.exit();
    return written.finally(() => this.enter());
  }

  // Writes what waits once every running operation waits on the collector (or a chunk is full), up to
  // FLUSHES_AT_ONCE chunks at a time
  private maybeFlush() {
    while (this.flushing < FLUSHES_AT_ONCE) {
      const queued = this.entities.length + this.relations.length;
      if (queued === 0) return;
      const runningMayAddMore = this.active > 0 && queued < MAX_CHUNK;
      if (runningMayAddMore) return;
      this.flush().catch(() => {});
    }
  }

  // Takes the next chunk synchronously (before the first await), so maybeFlush sees the queues shrink
  private async flush() {
    this.flushing += 1;
    try {
      const entities = this.entities.splice(0, MAX_CHUNK);
      const relations = this.relations.splice(0, MAX_CHUNK);
      await this.write(entities, (user, creates) => {
        return writeEntityChunk(this.writeContext(), user, creates.map(({ type, input }) => ({ type, input })), newCounters(), { missingEnds: 'error', readRefs: this.readRefs });
      });
      await this.write(relations, (user, creates) => {
        return writeRelationChunk(this.writeContext(), user, creates.map(({ input }) => input), newCounters(), { missingEnds: 'error', readRefs: this.readRefs });
      });
    } finally {
      this.flushing -= 1;
    }
    this.maybeFlush();
  }

  private writeContext(): AuthContext {
    return { ...this.context, lockfree_write: true, lockfree_batch: undefined } as AuthContext;
  }

  // Writes the held creates, one chunk per user, and settles each one with its element or its error
  private async write(pending: PendingCreate[], writeChunk: (user: AuthUser, creates: PendingCreate[]) => Promise<ItemResult[]>) {
    const byUser = new Map<string, PendingCreate[]>();
    pending.forEach((create) => {
      const userCreates = byUser.get(create.user.internal_id);
      if (userCreates) userCreates.push(create);
      else byUser.set(create.user.internal_id, [create]);
    });
    for (const creates of byUser.values()) {
      try {
        const results = await writeChunk(creates[0].user, creates);
        results.filter((result) => result.status === 'created' || result.status === 'merged').forEach((result) => {
          const ids = result.element ? getInstanceIds(result.element) : [result.id];
          ids.forEach((id: string) => this.readRefs.delete(id.toLowerCase()));
        });
        const outcomes = await storedElements(results, creates.map((create) => create.type));
        outcomes.forEach((outcome, i) => {
          if (outcome.element) creates[i].resolve(outcome.element);
          else creates[i].reject(outcome.error);
        });
      } catch (e) {
        creates.forEach((create) => create.reject(e));
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
  const isSingleCreate = document.definitions.length === 1 && definition.selectionSet.selections.length === 1
    && field?.selectionSet && field.name?.value?.endsWith('Add');
  if (!isSingleCreate) return document;
  const idOnly = { kind: Kind.SELECTION_SET, selections: [{ kind: Kind.FIELD, name: { kind: Kind.NAME, value: 'id' } }] };
  const selectionSet = { ...definition.selectionSet, selections: [{ ...field, selectionSet: idOnly }] };
  const rewritten = { ...document, definitions: [{ ...definition, selectionSet }] } as DocumentNode;
  return validate(schema, rewritten).length === 0 ? rewritten : document;
};

// A mutation ready to execute (with the name of its top field, whose id it answers), or why it is refused
type ParsedMutation = { document: DocumentNode; field: string } | { invalid: string };

const parseMutation = (schema: GraphQLSchema, query: string): ParsedMutation => {
  try {
    const document = parse(query);
    const errors = validate(schema, document);
    const definition: any = document.definitions[0];
    const field = definition?.selectionSet?.selections?.[0]?.name?.value;
    if (errors.length > 0 || definition?.operation !== 'mutation' || !field) {
      return { invalid: errors[0]?.message ?? 'Only mutations are accepted' };
    }
    return { document: idOnlyDocument(schema, document), field };
  } catch (e: any) {
    return { invalid: e.message };
  }
};

// Parsed mutations by query text: a batch sends the same few queries over and over
const parsedMutations = new Map<string, ParsedMutation>();
const mutationOf = (schema: GraphQLSchema, query: string) => {
  const cached = parsedMutations.get(query);
  if (cached) return cached;
  const parsed = parseMutation(schema, query);
  if (parsedMutations.size > 1000) parsedMutations.clear();
  parsedMutations.set(query, parsed);
  return parsed;
};

// Every string in a value, deep
const collectStrings = (value: any, out: Set<string>) => {
  if (typeof value === 'string') out.add(value);
  else if (Array.isArray(value)) value.forEach((item) => collectStrings(item, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((item) => collectStrings(item, out));
  return out;
};
export const replaceStrings = (value: any, ids: Map<string, string>): any => {
  if (typeof value === 'string') return ids.get(value) ?? value;
  if (Array.isArray(value)) return value.map((item) => replaceStrings(item, ids));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceStrings(item, ids)]));
  return value;
};

// The references of each operation to the others; references closing a cycle are left out
export const dependenciesOf = (operations: Operation[]) => {
  const indexByRef = new Map<string, number>();
  operations.forEach((operation, index) => {
    if (operation.ref) indexByRef.set(operation.ref, index);
  });
  const dependencies = operations.map((operation, index) => [...collectStrings(operation.variables ?? {}, new Set())]
    .map((value) => indexByRef.get(value))
    .filter((dependency): dependency is number => dependency !== undefined && dependency !== index));
  // Depth-first walk: a reference to an operation still being visited closes a cycle
  const state: ('unseen' | 'visiting' | 'visited')[] = operations.map(() => 'unseen');
  const visit = (index: number) => {
    state[index] = 'visiting';
    dependencies[index] = dependencies[index].filter((dependency) => {
      if (state[dependency] === 'visiting') return false; // cycle: run without waiting for it
      if (state[dependency] === 'unseen') visit(dependency);
      return true;
    });
    state[index] = 'visited';
  };
  operations.forEach((_, index) => {
    if (state[index] === 'unseen') visit(index);
  });
  return dependencies;
};

// The result of an executed mutation: its first error, or the id of what it created
const responseResult = (response: any, field: string): OperationResult => {
  if (response.errors?.length > 0) {
    const [error] = response.errors;
    return { status: 'error', error: error.message, code: error.extensions?.code ?? error.originalError?.name };
  }
  return { status: 'done', id: response.data?.[field]?.id };
};

export const executeOperations = async (context: AuthContext, schema: GraphQLSchema, operations: Operation[]): Promise<OperationResult[]> => {
  const collector = new WriteCollector(context);
  const batchContext = { ...context, lockfree_batch: collector } as AuthContext;
  const dependencies = dependenciesOf(operations);
  const realIds = new Map<string, string>(); // placeholder ref -> real id
  const results: OperationResult[] = operations.map(() => ({ status: 'error' }));
  const completions: Promise<void>[] = []; // by operation index, settled once the operation is done
  const run = async (index: number) => {
    const operation = operations[index];
    await Promise.all(dependencies[index].map((dependency) => completions[dependency]));
    const failedDependency = dependencies[index].find((dependency) => results[dependency].status === 'error');
    if (failedDependency !== undefined) {
      results[index] = { status: 'error', error: `Referenced object ${operations[failedDependency].ref} was not imported`, code: 'MISSING_REFERENCE_ERROR' };
      return;
    }
    const mutation = mutationOf(schema, operation.query);
    if ('invalid' in mutation) {
      results[index] = { status: 'error', error: mutation.invalid, code: 'GRAPHQL_VALIDATION_FAILED' };
      return;
    }
    collector.enter();
    try {
      const variableValues = replaceStrings(operation.variables ?? {}, realIds);
      const response = await execute({ schema, document: mutation.document, variableValues, contextValue: batchContext });
      const result = responseResult(response, mutation.field);
      results[index] = result;
      if (operation.ref && result.id) realIds.set(operation.ref, result.id);
    } catch (e: any) {
      results[index] = { status: 'error', error: e?.message ?? String(e), code: e?.extensions?.code ?? e?.name };
    } finally {
      collector.exit();
    }
  };
  // Every operation starts a microtask later, in input order, so that all the completions it awaits exist by then
  const allRegistered = Promise.resolve();
  operations.forEach((_, index) => {
    completions.push(allRegistered.then(() => run(index)));
  });
  await Promise.all(completions);
  return results;
};
