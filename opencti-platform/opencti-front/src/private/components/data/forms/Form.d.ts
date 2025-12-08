/**
 * Type definitions for Form components
 */

// Field type definitions
export interface FormFieldAttribute {
  id: string;
  name: string;
  label: string; // Display label for the field
  description?: string;
  type: string; // Field type: text, select, open vocabulary, etc.
  required: boolean;
  isMandatory?: boolean; // Whether this field is for a mandatory attribute
  width?: 'full' | 'half' | 'third'; // Field width in grid: full (12), half (6), third (4)
  entityType?: string; // The entity type this field belongs to (for field type filtering)
  attributeMapping: {
    entity: string; // Entity ID this field maps to (main_entity or additional entity ID)
    attributeName: string; // The attribute name on that entity
    mappingType?: 'direct' | 'nested'; // How the field maps to the entity
  };
  parseMode?: 'comma' | 'line'; // For text/textarea fields
  options?: Array<{ label: string; value: string }>; // For select/multiselect fields
  defaultValue?: string | number | boolean | string[] | Date | null; // Default value for the field
}

export interface AdditionalEntity {
  id: string;
  entityType: string; // Entity type
  label: string; // Display label for this entity in the form
  multiple: boolean; // Whether this entity allows multiple instances
  minAmount?: number; // For multiple entities, minimum required instances
  required?: boolean; // For non-multiple entities, whether it's required
  lookup?: boolean; // Whether this is an entity lookup (select existing entities)
  fieldMode?: 'multiple' | 'parsed'; // Whether to have multiple fields or parse a single field
  parseField?: 'text' | 'textarea'; // Type of field when using parsed mode
  parseMode?: 'comma' | 'line'; // How to parse the field (comma-separated or line-by-line)
  parseFieldMapping?: string; // Attribute name where parsed values should be stored when fieldMode is 'parsed'
  autoConvertToStixPattern?: boolean; // For Indicator type with parsed mode: automatically convert to STIX patterns
}

export interface EntityRelationship {
  id: string;
  fromEntity: string; // Entity ID (main_entity or additional entity ID)
  toEntity: string; // Entity ID (main_entity or additional entity ID)
  relationshipType: string; // Relationship type
  required?: boolean; // Whether this relationship is required
  fields?: FormFieldAttribute[]; // Additional fields for the relationship
}

export interface FormBuilderData {
  name: string;
  description?: string;
  mainEntityType: string;
  includeInContainer: boolean; // Whether to include entities in container (only for container types)
  isDraftByDefault: boolean; // Whether forms should be created as draft by default
  allowDraftOverride: boolean; // Whether users can override the draft setting
  mainEntityMultiple: boolean; // Whether main entity allows multiple
  mainEntityLookup?: boolean; // Whether main entity is an entity lookup (select existing entities)
  mainEntityFieldMode?: 'multiple' | 'parsed'; // Whether to have multiple fields or parse a single field
  mainEntityParseField?: 'text' | 'textarea'; // Type of field when using parsed mode for main entity
  mainEntityParseMode?: 'comma' | 'line'; // How to parse the field for main entity
  mainEntityParseFieldMapping?: string; // Attribute name where parsed values should be stored when fieldMode is 'parsed'
  mainEntityAutoConvertToStixPattern?: boolean; // For Indicator type with parsed mode: automatically convert to STIX patterns
  autoCreateIndicatorFromObservable?: boolean; // Auto-create indicators from observables
  autoCreateObservableFromIndicator?: boolean; // Auto-create observables from indicators
  additionalEntities: AdditionalEntity[];
  fields: FormFieldAttribute[];
  relationships: EntityRelationship[];
  active: boolean;
}

export interface FormAddInput {
  name: string;
  description?: string;
  form_schema: string;
  active?: boolean;
}

export interface FormEditInput {
  id: string;
  name?: string;
  description?: string;
  form_schema?: string;
  active?: boolean;
}

export interface FormSchemaDefinition {
  version: string;
  mainEntityType: string;
  includeInContainer?: boolean;
  isDraftByDefault?: boolean; // Whether forms should be created as draft by default
  allowDraftOverride?: boolean; // Whether users can override the draft setting
  mainEntityMultiple?: boolean;
  mainEntityLookup?: boolean;
  mainEntityFieldMode?: 'multiple' | 'parsed';
  mainEntityParseField?: 'text' | 'textarea';
  mainEntityParseMode?: 'comma' | 'line';
  mainEntityParseFieldMapping?: string; // Attribute name where parsed values should be stored when fieldMode is 'parsed'
  mainEntityAutoConvertToStixPattern?: boolean; // For Indicator type with parsed mode: automatically convert to STIX patterns
  autoCreateIndicatorFromObservable?: boolean; // Auto-create indicators from observables
  autoCreateObservableFromIndicator?: boolean; // Auto-create observables from indicators
  additionalEntities: AdditionalEntity[];
  fields: FormFieldDefinition[];
  relationships: FormRelationshipDefinition[];
}

export interface FormFieldDefinition {
  id: string;
  name: string;
  label: string;
  description?: string;
  type: string;
  required: boolean;
  isMandatory?: boolean;
  width?: 'full' | 'half' | 'third'; // Field width in grid: full (12), half (6), third (4)
  multiple?: boolean; // For openvocab and select/multiselect fields
  relationship?: {
    type: string;
    target: string;
    direction: 'forward' | 'reverse';
    includeInBundle: boolean;
  };
  attributeMapping: {
    entity: string;
    attributeName: string;
    mappingType?: 'direct' | 'nested'; // How the field maps to the entity
  };
  options?: Array<{ label: string; value: string }>; // For select/multiselect fields
  defaultValue?: string | number | boolean | string[] | Date | null;
}

export interface FormRelationshipDefinition {
  id: string;
  fromEntity: string;
  toEntity: string;
  relationshipType: string;
  required?: boolean;
  fields?: FormFieldDefinition[];
}

// Entity type definition for UI display
export interface EntityTypeOption {
  value: string;
  label: string;
  isContainer?: boolean;
  attributes?: AttributeOption[];
  defaultValuesAttributes?: AttributeOption[];
}

// Field type option for UI display
export interface FieldTypeOption {
  value: string;
  label: string;
}

// Attribute option for UI display
export interface AttributeOption {
  value: string;
  label: string;
  name: string;
  type?: string;
  mandatory?: boolean;
  multiple?: boolean;
  defaultValues?: { id: string; name: string; }[] | null;
}

// Relationship type option for UI display
export interface RelationshipTypeOption {
  value: string;
  label: string;
}
