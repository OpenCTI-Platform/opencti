// ---------------------------------------------------------------------------
// Raw format of public/schema.json, as written by scripts/generate-graph.ts.
// Only normalizeSchema() should read these shapes; the rest of the app works
// on the normalized model below.
// ---------------------------------------------------------------------------

export type RawAttributeType = 'string' | 'date' | 'numeric' | 'boolean' | 'object';

/**
 * - external: required from the user
 * - customizable: optional, can be made mandatory in entity settings
 * - internal: managed by the platform
 * - no: optional
 */
export type MandatoryType = 'external' | 'customizable' | 'internal' | 'no';

export interface RawAttribute {
  name: string;
  type: RawAttributeType;
  format?: string;
  label: string;
  multiple: boolean;
  mandatory: MandatoryType;
  description?: string;
  isStix: boolean;
}

/** An entity or relationship type definition, or a relation "slot" (`<source>_<name>`) when `stixType` is set. */
export interface RawTypeNode {
  id: string;
  type: 'entity' | 'relationship';
  data: {
    label: string;
    isRelationship: boolean;
    attributes: RawAttribute[];
    /** Slots only: 'builtin' | 'extended' | 'new' for core relationships, the ref name for ref attributes. */
    stixType?: string;
    isRefAttribute?: boolean;
  };
}

export interface RawTargetGroupNode {
  id: string;
  type: 'target-group';
  data: {
    label: string;
    items: Array<{ label: string; isRelationship: boolean }>;
    isDuplicate: boolean;
  };
}

export type RawNode = RawTypeNode | RawTargetGroupNode;

export interface RawEdge {
  id: string;
  source: string;
  target: string;
  /** 'is-a' for inheritance (source = child, target = parent), '' otherwise. */
  label: string;
}

export interface RawSchema {
  nodes: RawNode[];
  edges: RawEdge[];
}

// ---------------------------------------------------------------------------
// Normalized model, built once at load time.
// ---------------------------------------------------------------------------

export type SchemaCategory = 'SDO' | 'SCO' | 'SRO' | 'Meta' | 'Internal' | 'Abstract';

/** Categories the user can switch on and off. Abstract roots only appear as ancestors or search hits. */
export type ToggleableCategory = Exclude<SchemaCategory, 'Abstract'>;

export type SchemaTypeKind = 'entity' | 'relationship';

export interface AttributeDef extends RawAttribute {
  /** Top-most ancestor declaring this attribute; the owning type itself when not inherited. */
  declaredBy: string;
}

export interface SchemaType {
  id: string;
  label: string;
  kind: SchemaTypeKind;
  category: SchemaCategory;
  /** Has subtypes. Abstract types are never instantiated directly in OpenCTI. */
  isAbstract: boolean;
  parentId: string | null;
  childIds: string[];
  /** Root first, direct parent last. */
  ancestorIds: string[];
  attributes: AttributeDef[];
}

export type RelationKind = 'relationship' | 'ref';

/** How a core relationship relates to the STIX 2.1 specification. */
export type StixStatus = 'builtin' | 'extended' | 'new';

/** A relation that a source type can hold: a core relationship (`uses`) or a ref attribute (`objectMarking`). */
export interface SchemaRelation {
  /** `<sourceTypeId>_<name>`, as in schema.json. */
  id: string;
  name: string;
  kind: RelationKind;
  /** null for ref attributes. */
  stixStatus: StixStatus | null;
  sourceTypeId: string;
  /** Declared targets. An abstract target also accepts all of its descendants. */
  targetTypeIds: string[];
  /** Relationship type carrying the attributes of this relation (e.g. `uses`); null for ref attributes. */
  relationshipTypeId: string | null;
}

export interface NormalizedSchema {
  types: ReadonlyMap<string, SchemaType>;
  relations: ReadonlyMap<string, SchemaRelation>;
  /** Every type id, sorted by label. */
  typeIds: string[];
  /** typeId → relations declared on that type, sorted by name. */
  outgoing: ReadonlyMap<string, string[]>;
  /** typeId → relations that declare that type as a target, sorted by name. */
  incoming: ReadonlyMap<string, string[]>;
  categoryCounts: Readonly<Record<SchemaCategory, number>>;
}

// ---------------------------------------------------------------------------
// Find path
// ---------------------------------------------------------------------------

export interface PathStep {
  relationId: string;
  fromTypeId: string;
  toTypeId: string;
  /** 'out' follows the relation from source to target, 'in' walks it backwards. */
  direction: 'out' | 'in';
  /** Abstract target declared by the relation when the concrete endpoint is one of its descendants. */
  viaTypeId: string | null;
}

export interface SchemaPath {
  fromTypeId: string;
  toTypeId: string;
  /** Types along the path, from start to end. */
  typeIds: string[];
  steps: PathStep[];
}
