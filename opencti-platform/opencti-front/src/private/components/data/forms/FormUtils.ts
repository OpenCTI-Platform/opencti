/**
 * Utility functions and constants for Form components
 */
import type { FormFieldAttribute, EntityTypeOption, AttributeOption, RelationshipTypeOption, FormBuilderData, FormSchemaDefinition } from './Form.d';
import { getOpenVocabAttributes, getVocabularyMappingByAttribute } from '../../../../utils/vocabularyMapping';

// Field type options for the UI
export const FIELD_TYPES = [
  { value: 'text', label: 'Text' },
  { value: 'textarea', label: 'Text Area' },
  { value: 'number', label: 'Number' },
  { value: 'select', label: 'Select' },
  { value: 'multiselect', label: 'Multi-Select' },
  { value: 'checkbox', label: 'Checkbox' },
  { value: 'toggle', label: 'Toggle' },
  { value: 'datetime', label: 'Date & Time' },
  { value: 'createdBy', label: 'Created By' },
  { value: 'objectMarking', label: 'Object Marking' },
  { value: 'objectLabel', label: 'Object Label' },
  { value: 'externalReferences', label: 'External References' },
  { value: 'files', label: 'Files' },
  { value: 'openvocab', label: 'Open Vocabulary' },
];

// Field type to attribute type mapping
export const FIELD_TYPE_TO_ATTRIBUTE_TYPE: Record<string, string[]> = {
  text: ['string'],
  textarea: ['string', 'markdown', 'text'],
  number: ['numeric', 'integer', 'float'],
  select: ['string', 'enum'],
  multiselect: ['string[]', 'enum[]', 'string'], // string fields with multiple=true
  checkbox: ['boolean'],
  toggle: ['boolean'],
  datetime: ['date'],
  createdBy: ['ref'], // Special reference field
  objectMarking: ['refs'], // Multiple references
  objectLabel: ['refs'], // Multiple references
  externalReferences: ['refs'], // External references
  files: ['files'], // File uploads
  openvocab: ['string'], // OpenVocab fields are string attributes with special rendering
};

// Container types (backend constants)
export const CONTAINER_TYPES = [
  'Case-Incident',
  'Case-Rfi',
  'Case-Rft',
  'Feedback',
  'Task',
  'Note',
  'Observed-Data',
  'Opinion',
  'Report',
  'Grouping',
];

/**
 * Generate a unique ID for a field
 */
export const generateFieldId = () => `field-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

/**
 * Generate a unique ID for an entity
 */
export const generateEntityId = () => `entity-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

/**
 * Generate a unique ID for a relationship
 */
export const generateRelationshipId = () => `rel-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

/**
 * Get available field types based on entity attributes
 * @param entityType The entity type to check
 * @param entityTypes The list of available entity types
 * @returns List of field types that have matching attributes
 */
export const getAvailableFieldTypes = (
  entityType: string,
  entityTypes: EntityTypeOption[],
): typeof FIELD_TYPES => {
  const entity = entityTypes.find((e) => e.value === entityType);
  if (!entity || !entity.attributes) return FIELD_TYPES;

  const { attributes } = entity;

  // Special field types that are always available
  const specialFieldTypes = ['createdBy', 'objectMarking', 'objectLabel', 'externalReferences', 'files'];

  // Get list of attributes that support OpenVocab
  const openVocabAttributeNames = getOpenVocabAttributes();

  // Check which field types have matching attributes
  return FIELD_TYPES.filter((fieldType) => {
    // Special field types are always available
    if (specialFieldTypes.includes(fieldType.value)) {
      return true;
    }

    // For OpenVocab field type, check if any attributes match our vocabulary mapping
    if (fieldType.value === 'openvocab') {
      return attributes.some((attr: AttributeOption) => openVocabAttributeNames.includes(attr.name));
    }

    const allowedAttributeTypes = FIELD_TYPE_TO_ATTRIBUTE_TYPE[fieldType.value] || [];

    return attributes.some((attr: AttributeOption) => {
      // Skip 'ref', 'refs', and 'object' type attributes
      const attrType = attr.type || 'string';
      if (attrType === 'ref' || attrType === 'refs' || attrType === 'object') {
        return false;
      }

      // Check if this attribute matches any of the allowed types for this field
      return allowedAttributeTypes.some((allowedType) => {
        // For multiselect, check if string attributes support multiple
        if (fieldType.value === 'multiselect' && attrType === 'string' && attr.multiple) {
          return true;
        }
        // For select, check if string attributes don't support multiple
        if (fieldType.value === 'select' && attrType === 'string' && !attr.multiple) {
          return true;
        }
        // Regular type matching
        return attrType === allowedType || attrType.includes(allowedType);
      });
    });
  });
};

/**
 * Get attributes for a specific entity type that match field type
 * @param entityType The entity type to get attributes for
 * @param fieldType The field type to filter attributes by
 * @param entityTypes The list of available entity types
 * @param t_i18n Translation function
 * @returns List of attribute options
 */
export const getAttributesForEntityType = (
  entityType: string,
  fieldType: string,
  entityTypes: EntityTypeOption[],
  t_i18n: (key: string) => string,
): AttributeOption[] => {
  // Handle special reference field types that map to exact attributes
  if (fieldType === 'createdBy') {
    return [{
      value: 'createdBy',
      name: 'createdBy',
      label: t_i18n('Created By'),
      mandatory: false,
    }];
  }

  if (fieldType === 'objectMarking') {
    return [{
      value: 'objectMarking',
      name: 'objectMarking',
      label: t_i18n('Marking Definitions'),
      mandatory: false,
    }];
  }

  if (fieldType === 'objectLabel') {
    return [{
      value: 'objectLabel',
      name: 'objectLabel',
      label: t_i18n('Labels'),
      mandatory: false,
    }];
  }

  if (fieldType === 'externalReferences') {
    return [{
      value: 'externalReferences',
      name: 'externalReferences',
      label: t_i18n('External References'),
      mandatory: false,
    }];
  }

  if (fieldType === 'files') {
    return [{
      value: 'x_opencti_files',
      name: 'x_opencti_files',
      label: t_i18n('Files'),
      mandatory: false,
    }];
  }

  const entity = entityTypes.find((e) => e.value === entityType);
  if (!entity || !entity.attributes) return [];

  // Get list of attributes that support OpenVocab
  const openVocabAttributeNames = getOpenVocabAttributes();

  // For OpenVocab field type, filter to only vocabulary-supported attributes
  if (fieldType === 'openvocab') {
    return (entity.attributes || [])
      .filter((attr: { name: string }) => openVocabAttributeNames.includes(attr.name))
      .map((attr: { type?: string; name: string; label?: string; mandatory?: boolean }) => ({
        value: attr.name,
        name: attr.name,
        label: attr.label || attr.name,
        mandatory: attr.mandatory || false,
        type: attr.type || 'string',
      }));
  }

  const allowedAttributeTypes = FIELD_TYPE_TO_ATTRIBUTE_TYPE[fieldType] || [];

  // Filter attributes based on their type
  return (entity.attributes || [])
    .filter((attr: { type?: string; name: string; label?: string; mandatory?: boolean; multiple?: boolean }) => {
      // Skip 'ref' and 'object' type attributes as they need special handling
      const attrType = attr.type || 'string';
      if (attrType === 'ref' || attrType === 'refs' || attrType === 'object') {
        return false;
      }

      // Check if attribute type matches field type
      return allowedAttributeTypes.some((allowedType) => {
        // For multiselect, include string attributes that support multiple
        if (fieldType === 'multiselect' && attrType === 'string' && attr.multiple) {
          return true;
        }
        // For select, include string attributes that don't support multiple
        if (fieldType === 'select' && attrType === 'string' && !attr.multiple) {
          return true;
        }
        // Regular type matching
        return attrType === allowedType || attrType.includes(allowedType);
      });
    })
    .map((attr: AttributeOption) => ({
      value: attr.name,
      name: attr.name,
      label: attr.label || t_i18n(attr.name),
      mandatory: attr.mandatory || false,
    }))
    .sort((a: { label: string }, b: { label: string }) => a.label.localeCompare(b.label));
};

/**
 * Get relationship types available for specific entity combinations
 * @param mainEntityType The main entity type
 * @param additionalEntityTypes The additional entity types
 * @param schema The schema object from useAuth
 * @param t_i18n Translation function
 * @returns List of relationship type options
 */
export const getAvailableRelationships = (
  mainEntityType: string,
  additionalEntityTypes: string[],
  schema: { scrs?: Array<{ id: string; label?: string }>; schemaRelationsTypesMapping?: Map<string, readonly string[]> },
  t_i18n: (key: string) => string,
): RelationshipTypeOption[] => {
  if (!mainEntityType || !schema) return [];

  const { scrs, schemaRelationsTypesMapping } = schema;
  if (!scrs || !schemaRelationsTypesMapping) return [];

  const allRelationshipTypes = scrs.map((s: { id: string; label?: string }) => ({
    value: s.id,
    label: t_i18n(`relationship_${s.id}`),
  }));

  // Get all entity types involved (main + additional)
  const allEntityTypes = [mainEntityType, ...additionalEntityTypes];

  // Collect all possible relationships for all entity types
  const allMappings = new Set<string>();
  allEntityTypes.forEach((entityType) => {
    const mappings = schemaRelationsTypesMapping.get(entityType) || [];
    mappings.forEach((mapping: string) => allMappings.add(mapping));
  });

  // Return relationships that are valid for at least one entity type
  const validRelationships = allRelationshipTypes.filter((rel: RelationshipTypeOption) => {
    return allMappings.has(rel.value);
  });

  return validRelationships;
};

// Helper to convert attribute type to field type for forms
const mapAttributeTypeToFieldType = (attrType: string, attrName: string): string => {
  if (attrName === 'x_opencti_main_observable_type') return 'types';
  if (attrName === 'createdBy') return 'ref';
  if (attrName === 'objectLabel' || attrName === 'objectMarking') return 'refs';
  if (attrType === 'date') return 'datetime';
  if (attrType === 'boolean') return 'checkbox';
  if (attrType === 'numeric' || attrType === 'integer' || attrType === 'float') return 'number';
  if (attrType === 'markdown' || attrType === 'text') return 'textarea';
  // Default to text for string and other types
  return 'text';
};

/**
 * Get initial mandatory fields for default entity type
 * @param entityType The entity type to get mandatory fields for
 * @param entityTypes The list of available entity types
 * @param t_i18n Translation function
 * @returns List of mandatory fields with default values
 */
export const getInitialMandatoryFields = (
  entityType: string,
  entityTypes: EntityTypeOption[],
  t_i18n: (key: string) => string,
): FormFieldAttribute[] => {
  const entity = entityTypes.find((e) => e.value === entityType);

  if (!entity || !entity.attributes) {
    return [];
  }

  // Filter mandatory attributes (mandatoryType === 'external' means truly mandatory)
  const mandatoryAttributes = entity.attributes.filter((attr: AttributeOption & { mandatoryType?: string }) => attr.mandatory || attr.mandatoryType === 'external');

  // Pre-populate fields for mandatory attributes with default values if available
  return mandatoryAttributes.map((attr: AttributeOption & { defaultValues?: Array<{ id: string; name: string }> | null; mandatoryType?: string; type?: string }) => {
    const defaultValue = (attr.defaultValues && attr.defaultValues.length && attr.defaultValues.length > 0) ? attr.defaultValues[0] : null;

    // Convert attribute type to appropriate field type
    let fieldType = mapAttributeTypeToFieldType(attr.type || 'string', attr.name);
    const vocabMapping = getVocabularyMappingByAttribute(attr.name);
    if (vocabMapping) {
      fieldType = 'openvocab';
    }

    return {
      id: generateFieldId(),
      name: attr.name,
      label: attr.label || t_i18n(attr.name),
      description: '',
      type: fieldType,
      required: true,
      isMandatory: true, // Mark as mandatory attribute field
      entityType, // Add entityType for field type filtering
      attributeMapping: {
        entity: 'main_entity',
        attributeName: attr.name,
        mappingType: 'direct',
      },
      ...(defaultValue ? { defaultValue: defaultValue.id || defaultValue.name } : {}),
    };
  });
};

/**
 * Build entity types from schema with translations and attributes
 * @param schema The schema object from useAuth
 * @param entitySettings The entity settings from query with attributesDefinitions
 * @param t_i18n Translation function
 * @returns List of entity type options
 */
type EntitySettingNode = {
  target_type: string;
  mandatoryAttributes?: ReadonlyArray<string>;
  attributesDefinitions?: ReadonlyArray<{
    type: string;
    name: string;
    label?: string | null;
    mandatory: boolean;
    mandatoryType?: string;
    multiple?: boolean | null;
    defaultValues?: ReadonlyArray<{ id: string; name: string }> | null;
  }>;
};

export const buildEntityTypes = (
  schema: { scos?: Array<{ id: string; label?: string }>; sdos?: Array<{ id: string; label?: string }>; smos?: Array<{ id: string; label?: string }> },
  entitySettings: { edges: ReadonlyArray<{ node: EntitySettingNode }> },
  t_i18n: (key: string) => string,
): EntityTypeOption[] => {
  const { sdos, scos, smos } = schema;

  // Create a map of entity settings for quick lookup
  const settingsMap = new Map<string, EntitySettingNode>();
  entitySettings?.edges?.forEach(({ node }) => {
    if (node && 'target_type' in node) {
      settingsMap.set(node.target_type, node);
    }
  });

  const processEntityType = (s: { id: string; label?: string }) => {
    const settings = settingsMap.get(s.id);

    // Use attributesDefinitions from the query which contains full attribute info
    const attributesDefinitions = settings?.attributesDefinitions || [];
    const mandatoryAttrs = settings?.mandatoryAttributes || [];

    // Map attributesDefinitions to the format expected by the form
    const attributes = attributesDefinitions.map((attr) => ({
      value: attr.name,
      name: attr.name,
      label: attr.label || attr.name,
      type: attr.type,
      mandatory: attr.mandatory,
      mandatoryType: attr.mandatoryType,
      multiple: attr.multiple === null ? undefined : attr.multiple,
      defaultValues: attr.defaultValues as { id: string; name: string }[] | null | undefined,
    }));

    return {
      value: s.id,
      label: t_i18n(`entity_${s.id}`),
      isContainer: CONTAINER_TYPES.includes(s.id),
      attributes,
      mandatoryAttributes: mandatoryAttrs,
    };
  };

  const types = [
    ...(sdos || []).map(processEntityType),
    ...(scos || []).map(processEntityType),
    ...(smos || []).map(processEntityType),
  ].sort((a, b) => a.label.localeCompare(b.label));

  return types;
};

/**
 * Convert FormBuilderData to FormSchemaDefinition for backend
 * @param values The form builder data from UI
 * @returns The schema definition for backend
 */
export const convertFormBuilderDataToSchema = (
  values: FormBuilderData,
): FormSchemaDefinition => {
  return {
    version: '2.0',
    mainEntityType: values.mainEntityType,
    includeInContainer: values.includeInContainer,
    isDraftByDefault: values.isDraftByDefault,
    allowDraftOverride: values.allowDraftOverride,
    mainEntityMultiple: values.mainEntityMultiple,
    mainEntityLookup: values.mainEntityLookup,
    mainEntityFieldMode: values.mainEntityFieldMode,
    mainEntityParseField: values.mainEntityParseField,
    mainEntityParseMode: values.mainEntityParseMode,
    mainEntityParseFieldMapping: values.mainEntityParseFieldMapping,
    mainEntityAutoConvertToStixPattern: values.mainEntityAutoConvertToStixPattern,
    autoCreateIndicatorFromObservable: values.autoCreateIndicatorFromObservable,
    autoCreateObservableFromIndicator: values.autoCreateObservableFromIndicator,
    additionalEntities: values.additionalEntities,
    fields: values.fields.map((field) => ({
      id: field.id,
      name: field.name,
      label: field.label,
      description: field.description,
      type: field.type,
      required: field.required,
      isMandatory: field.isMandatory, // Preserve mandatory flag
      width: field.width, // Preserve field width configuration
      options: field.options,
      attributeMapping: field.attributeMapping,
      defaultValue: field.defaultValue,
    })),
    relationships: values.relationships,
  };
};
