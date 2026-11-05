import { type DocumentNode, getVariableValues, type GraphQLSchema, Kind, type OperationDefinitionNode, parse, validate } from 'graphql';
import Upload from 'graphql-upload/Upload.mjs';
import { ImportClientError, type ImportClient, UploadFile } from '../stix-import/types';
import { answerOperation, type DescribedOperation, describeOperation, standardIdOf } from './simulated-answers';

// The client of the dry intake: nothing is executed, every operation answers as the platform
// would (simulated-answers.ts). With a schema, it also pays what the GraphQL layer pays before
// any resolver: parse and validate once per document (Apollo caches both), coerce the variables
// on every call. A refused document or variable answers the GraphQL error the platform gives.
// Not paid: the per-request plugins of the platform's Apollo server, among them
// graphql-constraint-directive (@constraint); with graphql 17 the platform does not enforce
// @constraint on variables anyway (it reads a `coerced` field graphql 17 no longer returns), a
// separate issue: refusals match today, and diverge once that is fixed.

interface KnownDocument {
  operation: DescribedOperation;
  definition: OperationDefinitionNode;
  // The validation errors of the document, empty when valid
  errors: string[];
}

// Whether withUploads must rebuild a value: a file, or an object other than a plain one (its
// copy is a plain object), at any depth
const needsCopy = (value: unknown): boolean => {
  if (Array.isArray(value)) return value.some(needsCopy);
  if (value !== null && typeof value === 'object') return Object.getPrototypeOf(value) !== Object.prototype || Object.values(value).some(needsCopy);
  return false;
};

// A file is sent as a multipart part: give the Upload scalar what graphql-upload gives it. Only
// the path to a file is copied, the rest is given as is: a copy of plain objects and arrays
// would coerce the same, and copying every variable is a cost of this harness, not of the
// platform it measures.
const withUploads = (value: unknown): unknown => {
  if (value instanceof UploadFile) return new Upload();
  if (!needsCopy(value)) return value;
  if (Array.isArray(value)) return value.map(withUploads);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, withUploads(item)]));
  return value;
};

export class DryClient implements ImportClient {
  // Operations answered since the creation of the client
  operations = 0;

  private nextId = 0;

  private readonly documents = new Map<string, KnownDocument>();

  constructor(private readonly reads: Record<string, unknown>, private readonly schema: GraphQLSchema | null = null) {}

  private known(document: string): KnownDocument {
    let known = this.documents.get(document);
    if (!known) {
      const parsed: DocumentNode = parse(document);
      const definition = parsed.definitions.find((item) => item.kind === Kind.OPERATION_DEFINITION) as OperationDefinitionNode;
      const errors = this.schema ? validate(this.schema, parsed).map((error) => error.message) : [];
      known = { operation: describeOperation(document), definition, errors };
      this.documents.set(document, known);
    }
    return known;
  }

  async query(document: string, variables: Record<string, unknown> = {}) {
    this.operations += 1;
    const { operation, definition, errors } = this.known(document);
    if (errors.length > 0) {
      throw new ImportClientError('GRAPHQL_VALIDATION_FAILED', errors[0]);
    }
    if (this.schema) {
      const coerced = getVariableValues(this.schema, definition.variableDefinitions ?? [], withUploads(variables) as Record<string, unknown>);
      if (coerced.errors) {
        throw new ImportClientError('BAD_USER_INPUT', coerced.errors[0].message);
      }
    }
    return { [operation.root]: answerOperation(operation, variables, this.reads, () => this.newId(), standardIdOf) };
  }

  // An internal id as the platform answers one: a UUID, which the StixRef scalar accepts when the
  // transformation sends it back (fromId, toId...)
  private newId() {
    this.nextId += 1;
    return `00000000-0000-4000-8000-${this.nextId.toString(16).padStart(12, '0')}`;
  }
}
