import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_FORM = 'Form';

// Field types supported in forms
export enum FormFieldType {
  Text = 'text',
  Textarea = 'textarea',
  Select = 'select',
  MultiSelect = 'multiselect',
  Checkbox = 'checkbox',
  Date = 'date',
  DateTime = 'datetime',
}

// Additional entity configuration
export interface AdditionalEntity {
  id: string;
  type: string; // Entity type
  name: string; // Display name for this entity in the form
  multiple?: boolean; // Whether this entity allows multiple instances
  entityLookup?: boolean; // Whether this is an entity lookup (select existing entities)
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
  description?: string;
  type: FormFieldType;
  required: boolean;
  multiple?: boolean; // Allow multiple values (for text fields)
  parseMode?: 'comma' | 'line'; // For text/textarea fields that create entities
  stixPath?: string; // Path to STIX property (e.g., 'name', 'description', 'x_opencti_report_types')
  stixType?: string; // Entity type for entity fields (text/textarea with entity creation)
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
  from: string; // Entity ID (main_entity or additional entity ID)
  to: string; // Entity ID (main_entity or additional entity ID)
  type: string; // Relationship type
}

// Form schema definition
export interface FormSchemaDefinition {
  version: string; // Schema version for future compatibility
  mainEntityType: string; // Main entity type this form creates (e.g., 'Report', 'Incident')
  isContainer?: boolean; // Whether the main entity is a container
  mainEntityMultiple?: boolean; // Whether main entity allows multiple instances
  mainEntityLookup?: boolean; // Whether main entity is an entity lookup (select existing)
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
  form_schema: string; // JSON string of FormSchemaDefinition
  active: boolean;
}

export interface StoreEntityForm extends StoreEntity {
  name: string;
  description: string;
  form_schema: string;
  active: boolean;
}

// STIX representation
export interface StixForm extends StixObject {
  name: string;
  description: string;
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
    isContainer: { type: 'boolean' },
    additionalEntities: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          type: { type: 'string' },
          name: { type: 'string' },
          multiple: { type: 'boolean' },
          entityLookup: { type: 'boolean' },
        },
        required: ['id', 'type', 'name'],
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
          multiple: { type: 'boolean' },
          parseMode: {
            type: 'string',
            enum: ['comma', 'line']
          },
          stixPath: { type: 'string' },
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
          stixType: { type: 'string' },
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
