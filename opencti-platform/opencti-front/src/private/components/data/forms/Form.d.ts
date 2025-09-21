/**
 * Type definitions for Form components
 */

// Field type definitions
export interface FormFieldAttribute {
  id: string;
  name: string;
  label: string; // Display label for the field
  description?: string;
  type: string; // Field type: text, select, etc.
  required: boolean;
  isMandatory?: boolean; // Whether this field is for a mandatory attribute
  entityType?: string; // The entity type this field belongs to (for field type filtering)
  attributeMapping: {
    entity: string; // Entity ID this field maps to (main_entity or additional entity ID)
    attributeName: string; // The attribute name on that entity
    mappingType?: 'direct' | 'nested'; // How the field maps to the entity
  };
  fieldMode?: 'parsed' | 'multi'; // For fields in multiple entities
  parseMode?: 'comma' | 'line'; // For text/textarea with fieldMode='parsed'
  options?: Array<{ label: string; value: string }>; // For select/multiselect fields
  defaultValue?: any; // Default value for the field
}

export interface AdditionalEntity {
  id: string;
  entityType: string; // Entity type
  label: string; // Display label for this entity in the form
  multiple: boolean; // Whether this entity allows multiple instances
  lookup?: boolean; // Whether this is an entity lookup (select existing entities)
  fieldMode?: 'multiple' | 'parsed'; // Whether to have multiple fields or parse a single field
  parseField?: 'text' | 'textarea'; // Type of field when using parsed mode
  parseMode?: 'comma' | 'line'; // How to parse the field (comma-separated or line-by-line)
}

export interface EntityRelationship {
  id: string;
  fromEntity: string; // Entity ID (main_entity or additional entity ID)
  toEntity: string; // Entity ID (main_entity or additional entity ID)
  relationshipType: string; // Relationship type
  required?: boolean; // Whether this relationship is required
}

export interface FormBuilderData {
  name: string;
  description?: string;
  mainEntityType: string;
  mainEntityMultiple: boolean; // Whether main entity allows multiple
  mainEntityLookup?: boolean; // Whether main entity is an entity lookup (select existing entities)
  mainEntityFieldMode?: 'multiple' | 'parsed'; // Whether to have multiple fields or parse a single field
  mainEntityParseField?: 'text' | 'textarea'; // Type of field when using parsed mode for main entity
  mainEntityParseMode?: 'comma' | 'line'; // How to parse the field for main entity
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
  isContainer?: boolean;
  mainEntityMultiple?: boolean;
  mainEntityLookup?: boolean;
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
  parseMode?: 'comma' | 'line';
  stixPath?: string;
  stixType?: string;
  multiple?: boolean;
  relationship?: {
    type: string;
    target: string;
    direction: 'forward' | 'reverse';
    includeInBundle: boolean;
  };
  attributeMapping: {
    entity: string;
    attributeName: string;
  };
  fieldMode?: 'parsed' | 'multi';
  options?: Array<{ label: string; value: string }>; // For select/multiselect fields
  defaultValue?: any;
}

export interface FormRelationshipDefinition {
  id: string;
  fromEntity: string;
  toEntity: string;
  relationshipType: string;
  required?: boolean;
}

// Entity type definition for UI display
export interface EntityTypeOption {
  value: string;
  label: string;
  isContainer?: boolean;
  attributes?: any[];
  defaultValuesAttributes?: any[];
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
  mandatory?: boolean;
}

// Relationship type option for UI display
export interface RelationshipTypeOption {
  value: string;
  label: string;
}
