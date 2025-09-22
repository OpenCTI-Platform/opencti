import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_FORM = 'Form';

// Field types supported in forms
export enum FormFieldType {
  Text = 'text',
  Textarea = 'textarea',
  Number = 'number',
  Select = 'select',
  MultiSelect = 'multiselect',
  Checkbox = 'checkbox',
  Toggle = 'toggle',
  DateTime = 'datetime',
  CreatedBy = 'createdBy',
  ObjectMarking = 'objectMarking',
  ObjectLabel = 'objectLabel',
  Files = 'files',
}

// Additional entity configuration
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

// Relationship configuration
export interface FormFieldRelationship {
  type: string; // Type of relationship to create (e.g., 'uses', 'targets')
  target: 'main_entity' | string; // Target: main entity or another field ID
  direction?: 'from' | 'to'; // Direction of relationship (can be inferred)
  includeInBundle: boolean; // Should include related entities in the bundle
}

// Individual form field definition
export interface FormFieldDefinition {
  id: string;
  name: string;
  label: string; // Display label for the field
  description?: string;
  type: FormFieldType;
  required: boolean;
  isMandatory?: boolean; // Whether this field is for a mandatory attribute
  attributeMapping: {
    entity: string; // Entity ID this field maps to (main_entity or additional entity ID)
    attributeName: string; // The attribute name on that entity
    mappingType?: 'direct' | 'nested'; // How the field maps to the entity
  };
  defaultValue?: any;
  options?: Array<{ label: string; value: string }>; // For select fields
  relationship?: FormFieldRelationship; // Relationship configuration
  validation?: {
    minLength?: number;
    maxLength?: number;
    pattern?: string;
    min?: number;
    max?: number;
  };
}

// Form relationship definition
export interface FormRelationshipDefinition {
  id: string;
  fromEntity: string; // Entity ID (main_entity or additional entity ID)
  toEntity: string; // Entity ID (main_entity or additional entity ID)
  relationshipType: string; // Relationship type
  required?: boolean; // Whether this relationship is required
}

// Form schema definition
export interface FormSchemaDefinition {
  version: string; // Schema version for future compatibility
  mainEntityType: string; // Main entity type this form creates (e.g., 'Report', 'Incident')
  isContainer?: boolean; // Whether the main entity is a container
  mainEntityMultiple?: boolean; // Whether main entity allows multiple instances
  mainEntityLookup?: boolean; // Whether main entity is an entity lookup (select existing)
  mainEntityFieldMode?: 'multiple' | 'parsed'; // Whether to have multiple fields or parse a single field
  mainEntityParseField?: 'text' | 'textarea'; // Type of field when using parsed mode for main entity
  mainEntityParseMode?: 'comma' | 'line'; // How to parse the field for main entity
  additionalEntities?: AdditionalEntity[]; // Additional entities to include in the form
  fields: FormFieldDefinition[];
  relationships?: FormRelationshipDefinition[]; // Relationships between entities
  // Optional configurations
  markings?: string[]; // Default markings to apply
  confidence?: number; // Default confidence level
  createdByRef?: string; // Default creator reference
}

// Store entities
export interface BasicStoreEntityForm extends BasicStoreEntity {
  name: string;
  description: string;
  main_entity_type: string;
  form_schema: string; // JSON string of FormSchemaDefinition
  active: boolean;
}

export interface StoreEntityForm extends StoreEntity {
  name: string;
  description: string;
  main_entity_type: string;
  form_schema: string;
  active: boolean;
}

// STIX representation
export interface StixForm extends StixObject {
  name: string;
  description: string;
  main_entity_type: string;
  form_schema: string;
  active: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}

// Parsed form with schema object
export type FormParsed = Omit<BasicStoreEntityForm, 'form_schema'> & {
  form_schema: FormSchemaDefinition;
};

// Form submission data
export interface FormSubmissionData {
  formId: string;
  values: Record<string, any>;
  confidence?: number;
  userId?: string;
}

// JSON Schema for validation
export const FormSchemaDefinitionSchema: Record<string, any> = {
  type: 'object',
  properties: {
    version: { type: 'string' },
    mainEntityType: { type: 'string' },
    mainEntityMultiple: { type: 'boolean' },
    mainEntityLookup: { type: 'boolean' },
    mainEntityFieldMode: {
      type: 'string',
      enum: ['multiple', 'parsed']
    },
    mainEntityParseField: {
      type: 'string',
      enum: ['text', 'textarea']
    },
    mainEntityParseMode: {
      type: 'string',
      enum: ['comma', 'line']
    },
    isContainer: { type: 'boolean' },
    additionalEntities: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          entityType: { type: 'string' },
          label: { type: 'string' },
          multiple: { type: 'boolean' },
          lookup: { type: 'boolean' },
          fieldMode: {
            type: 'string',
            enum: ['multiple', 'parsed']
          },
          parseField: {
            type: 'string',
            enum: ['text', 'textarea']
          },
          parseMode: {
            type: 'string',
            enum: ['comma', 'line']
          },
        },
        required: ['id', 'entityType', 'label'],
      },
    },
    relationships: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          from: { type: 'string' },
          to: { type: 'string' },
          type: { type: 'string' },
        },
        required: ['id', 'from', 'to', 'type'],
      },
    },
    fields: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          description: { type: 'string' },
          type: {
            type: 'string',
            enum: Object.values(FormFieldType),
          },
          required: { type: 'boolean' },
          defaultValue: {
            oneOf: [
              { type: 'string' },
              { type: 'number' },
              { type: 'boolean' },
              { type: 'object' },
              { type: 'array' },
              { type: 'null' }
            ]
          },
          options: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                label: { type: 'string' },
                value: { type: 'string' },
              },
              required: ['label', 'value'],
            },
          },
          relationship: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              target: { type: 'string' },
              direction: {
                type: 'string',
                enum: ['from', 'to'],
              },
              includeInBundle: { type: 'boolean' },
            },
            required: ['type', 'target', 'includeInBundle'],
          },
          validation: {
            type: 'object',
            properties: {
              minLength: { type: 'integer' },
              maxLength: { type: 'integer' },
              pattern: { type: 'string' },
              min: { type: 'number' },
              max: { type: 'number' },
            },
            required: [],
          },
        },
        required: ['id', 'name', 'type', 'required'],
      },
    },
    markings: {
      type: 'array',
      nullable: true,
      items: { type: 'string' },
    },
    confidence: { type: 'integer', nullable: true },
    createdByRef: { type: 'string', nullable: true },
  },
  required: ['version', 'mainEntityType', 'fields'],
  additionalProperties: false,
};
