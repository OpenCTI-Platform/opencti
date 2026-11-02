import { type FieldNode, Kind, type OperationDefinitionNode, parse } from 'graphql';
import { convertTypeToStixType } from '../../database/stix-2-1-converter';
import { isBasicObject } from '../../schema/stixCoreObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';

// The platform's answers as the transformation reads them back, without a platform: shared by the
// conformance client (tests/01-unit/import-conformance, which mirrors the client-python recorder)
// and the dry intake client. The transformation reads id and entity_type of what it creates
// (entity_type drives the multiple-fields path) and sends the id back in later operations, so the
// id must be one the platform's scalars accept (a UUID). It also reads the standard_id of the
// observables it creates for an observed-data (its objects): the conformance client answers it as
// pycti's recorder does, the dry client as the platform does, a STIX id (see standardIdOf).

export const EMPTY_CONNECTION = {
  edges: [],
  pageInfo: { startCursor: null, endCursor: null, hasNextPage: false, hasPreviousPage: false, globalCount: 0 },
};
// Inputs the platform answers as an object, not echoed
const REFERENCE_INPUTS = new Set(['createdBy']);

export interface DescribedOperation {
  op: string;
  name: string | null;
  root: string;
  // The nested operation of a *Edit root, or of a nested field with arguments
  sub: string | null;
  // The root field returns a scalar
  scalar: boolean;
}

export const describeOperation = (document: string): DescribedOperation => {
  const operation = parse(document).definitions.find((definition) => definition.kind === Kind.OPERATION_DEFINITION) as OperationDefinitionNode;
  const rootField = operation.selectionSet.selections[0] as FieldNode;
  const nested = rootField.selectionSet?.selections[0] as FieldNode | undefined;
  const isOperation = nested !== undefined && ((nested.arguments?.length ?? 0) > 0 || rootField.name.value.endsWith('Edit'));
  return {
    op: operation.operation,
    name: operation.name?.value ?? null,
    root: rootField.name.value,
    sub: isOperation ? (nested as FieldNode).name.value : null,
    scalar: rootField.selectionSet === undefined,
  };
};

const entityType = (root: string, variables: any) => {
  const input = variables?.input;
  if (root === 'stixCyberObservableAdd' && variables.type) {
    return variables.type;
  }
  if (input && typeof input === 'object' && typeof input.relationship_type === 'string') {
    return input.relationship_type;
  }
  const name = root.endsWith('Add') ? root.slice(0, -3) : root;
  return name.charAt(0).toUpperCase() + name.slice(1);
};

const echoInput = (variables: any) => {
  const input = variables?.input;
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {};
  }
  return Object.fromEntries(Object.entries(input).filter(([key, value]) => !REFERENCE_INPUTS.has(key)
    && (value === null || ['string', 'number', 'boolean'].includes(typeof value))));
};

// The standard_id the recorder answers: the stix_id of the input, else the id
const recordedStandardId = (variables: any, entity: string, identifier: string) => {
  const stixId = variables?.input && typeof variables.input === 'object' ? variables.input.stix_id : null;
  return stixId || identifier;
};

// The platform type of a created element: the name of its root when it is one (StixFile, IPv4-Addr
// given beside an observable, SecurityPlatform), else that name with dashes (attackPatternAdd:
// AttackPattern for Attack-Pattern)
const platformType = (variables: any, entity: string) => {
  if (typeof variables?.input?.relationship_type === 'string') {
    return 'relationship';
  }
  if (entity === 'StixSightingRelationship') {
    return STIX_SIGHTING_RELATIONSHIP;
  }
  return isBasicObject(entity) ? entity : entity.replace(/([a-z0-9])([A-Z])/g, '$1-$2');
};

// The standard_id the platform answers: a STIX id, the one given (in the input, or beside it for an
// observable), else one of the STIX type of the created element (file, sighting, identity...)
export const standardIdOf = (variables: any, entity: string, identifier: string) => {
  const given = [variables?.input?.stix_id, variables?.stix_id].find((value) => typeof value === 'string' && value.includes('--'));
  if (given) {
    return given;
  }
  return `${convertTypeToStixType(platformType(variables, entity))}--${identifier}`;
};

// The answer to one operation: a read answers from `reads` (else an empty connection for a list,
// null otherwise), a mutation answers the created element with the id given by `newId`
export const answerOperation = (
  operation: DescribedOperation,
  variables: any,
  reads: Record<string, unknown>,
  newId: () => string,
  standardId: (variables: any, entity: string, identifier: string) => string = recordedStandardId,
) => {
  const { root, sub } = operation;
  if (operation.op === 'query') {
    if (root in reads) {
      return JSON.parse(JSON.stringify(reads[root]));
    }
    return root.endsWith('s') ? JSON.parse(JSON.stringify(EMPTY_CONNECTION)) : null;
  }
  const identifier = newId();
  if (operation.scalar) {
    return identifier;
  }
  const type = entityType(root, variables);
  const entity = { ...echoInput(variables), id: identifier, standard_id: standardId(variables, type, identifier), entity_type: type, parent_types: [] };
  return sub ? { [sub]: entity } : entity;
};
