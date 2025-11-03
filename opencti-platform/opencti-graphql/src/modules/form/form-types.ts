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
  ExternalReferences = 'externalReferences',
  Files = 'files',
  OpenVocab = 'openvocab',
  Types = 'types',
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
  parseFieldMapping: string; // Attribute name where parsed values should be stored when fieldMode is 'parsed'
  autoConvertToStixPattern?: boolean; // For Indicator type with parsed mode: automatically convert to STIX patterns
  required?: boolean;
  minAmount?: number;
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
  width?: 'full' | 'half' | 'third'; // Field width in grid: full (12), half (6), third (4)
  multiple?: boolean; // For openvocab and select/multiselect fields
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
  fields?: FormFieldDefinition[]; // Additional fields for the relationship
}

// Form schema definition
export interface FormSchemaDefinition {
  version: string; // Schema version for future compatibility
  mainEntityType: string; // Main entity type this form creates (e.g., 'Report', 'Incident')
  includeInContainer?: boolean; // Whether to include entities in container (only for container types)
  isDraftByDefault?: boolean; // Whether forms should be created as draft by default
  allowDraftOverride?: boolean; // Whether users can override the draft setting
  mainEntityMultiple?: boolean; // Whether main entity allows multiple instances
  mainEntityLookup?: boolean; // Whether main entity is an entity lookup (select existing)
  mainEntityFieldMode?: 'multiple' | 'parsed'; // Whether to have multiple fields or parse a single field
  mainEntityParseField?: 'text' | 'textarea'; // Type of field when using parsed mode for main entity
  mainEntityParseMode?: 'comma' | 'line'; // How to parse the field for main entity
  mainEntityParseFieldMapping?: string; // Attribute name where parsed values should be stored when fieldMode is 'parsed'
  mainEntityAutoConvertToStixPattern?: boolean; // For Indicator type with parsed mode: automatically convert to STIX patterns
  autoCreateIndicatorFromObservable?: boolean; // Auto-create indicators from observables
  autoCreateObservableFromIndicator?: boolean; // Auto-create observables from indicators
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
    mainEntityParseFieldMapping: { type: 'string' },
    mainEntityAutoConvertToStixPattern: { type: 'boolean' },
    autoCreateIndicatorFromObservable: { type: 'boolean' },
    autoCreateObservableFromIndicator: { type: 'boolean' },
    includeInContainer: { type: 'boolean' },
    isDraftByDefault: { type: 'boolean' },
    allowDraftOverride: { type: 'boolean' },
    additionalEntities: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          entityType: { type: 'string' },
          label: { type: 'string' },
          multiple: { type: 'boolean' },
          minAmount: { type: 'number', minimum: 0 },
          required: { type: 'boolean' },
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
          parseFieldMapping: { type: 'string' },
          autoConvertToStixPattern: { type: 'boolean' },
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
          fromEntity: { type: 'string' },
          toEntity: { type: 'string' },
          relationshipType: { type: 'string' },
        },
        required: ['id', 'fromEntity', 'toEntity', 'relationshipType'],
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
          width: {
            type: 'string',
            enum: ['full', 'half', 'third'],
          },
          multiple: {
            type: 'boolean',
          },
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
