/**
 * Type definitions for Form components
 */

// Field type definitions
export interface FormFieldAttribute {
  id: string;
  name: string;
  description?: string;
  type: string; // Field type: text, select, etc.
  required: boolean;
  isMandatory?: boolean; // Whether this field is for a mandatory attribute
  attributeMapping: {
    entity: string; // Entity ID this field maps to (main_entity or additional entity ID)
    attribute: string; // The attribute name on that entity
  };
  fieldMode?: 'parsed' | 'multi'; // For fields in multiple entities
  parseMode?: 'comma' | 'line'; // For text/textarea with fieldMode='parsed'
  defaultValue?: any; // Default value for the field
}

export interface AdditionalEntity {
  id: string;
  type: string; // Entity type
  name: string; // Display name for this entity in the form
  multiple: boolean; // Whether this entity allows multiple instances
  entityLookup?: boolean; // Whether this is an entity lookup (select existing entities)
}

export interface EntityRelationship {
  id: string;
  from: string; // Entity ID (main_entity or additional entity ID)
  to: string; // Entity ID (main_entity or additional entity ID)
  type: string; // Relationship type
}

export interface FormBuilderData {
  name: string;
  description?: string;
  mainEntityType: string;
  mainEntityMultiple: boolean; // Whether main entity allows multiple
  mainEntityLookup?: boolean; // Whether main entity is an entity lookup (select existing entities)
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
  description?: string;
  type: string;
  required: boolean;
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
    attribute: string;
  };
  fieldMode?: 'parsed' | 'multi';
  defaultValue?: any;
}

export interface FormRelationshipDefinition {
  id: string;
  from: string;
  to: string;
  type: string;
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
