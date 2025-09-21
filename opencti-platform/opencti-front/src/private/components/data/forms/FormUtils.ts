/**
 * Utility functions and constants for Form components
 */
import type { FormFieldAttribute, EntityTypeOption, AttributeOption, RelationshipTypeOption, FormBuilderData, FormSchemaDefinition } from './Form.d';

// Field type options for the UI
export const FIELD_TYPES = [
  { value: 'text', label: 'Text' },
  { value: 'textarea', label: 'Text Area' },
  { value: 'number', label: 'Number' },
  { value: 'select', label: 'Select' },
  { value: 'multiselect', label: 'Multi-Select' },
  { value: 'checkbox', label: 'Checkbox' },
  { value: 'datetime', label: 'Date & Time' },
];

// Field type to attribute type mapping
export const FIELD_TYPE_TO_ATTRIBUTE_TYPE: Record<string, string[]> = {
  text: ['string'],
  textarea: ['string', 'markdown', 'text'],
  number: ['numeric', 'integer', 'float'],
  select: ['string', 'enum'],
  multiselect: ['string[]', 'enum[]', 'string'], // string fields with multiple=true
  checkbox: ['boolean'],
  datetime: ['date'],
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
  const entity = entityTypes.find((e) => e.value === entityType);
  if (!entity || !entity.attributes) return [];

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
    .map((attr: { name: string; label?: string; mandatory?: boolean }) => ({
      value: attr.name,
      label: attr.label || t_i18n(attr.name),
      mandatory: attr.mandatory || false,
    }))
    .sort((a: { label: string }, b: { label: string }) => a.label.localeCompare(b.label));
};

/**
 * Get relationship types available for specific entity combinations
 * @param fromType The source entity type
 * @param toType The target entity type
 * @param schema The schema object from useAuth
 * @param t_i18n Translation function
 * @returns List of relationship type options
 */
export const getAvailableRelationships = (
  fromType: string,
  toType: string,
  schema: any,
  t_i18n: (key: string) => string,
): RelationshipTypeOption[] => {
  if (!fromType || !toType) return [];

  const { scrs, schemaRelationsTypesMapping } = schema;
  const allRelationshipTypes = scrs.map((s: any) => ({
    value: s.id,
    label: t_i18n(`relationship_${s.id}`),
  }));

  // Get mappings for both entity types
  const fromMappings = schemaRelationsTypesMapping?.get(fromType) || [];
  const toMappings = schemaRelationsTypesMapping?.get(toType) || [];

  // Only return relationships that are valid for BOTH entity types
  const validRelationships = allRelationshipTypes.filter((rel: RelationshipTypeOption) => {
    // A relationship is valid if it's in the mapping for either entity
    // (relationships are bidirectional)
    return fromMappings.includes(rel.value) || toMappings.includes(rel.value);
  });

  // If no specific mappings found, return empty (more restrictive)
  return validRelationships.length > 0 ? validRelationships : [];
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
  const mandatoryAttributes = entity.attributes.filter((attr: any) => 
    attr.mandatory || attr.mandatoryType === 'external'
  );

  // Pre-populate fields for mandatory attributes with default values if available
  return mandatoryAttributes.map((attr: any) => {
    const defaultValue = attr.defaultValues?.length > 0 ? attr.defaultValues[0] : null;

    // Convert attribute type to appropriate field type
    const fieldType = mapAttributeTypeToFieldType(attr.type);

    return {
      id: generateFieldId(),
      name: attr.label || t_i18n(attr.name),
      description: '',
      type: fieldType,
      required: true,
      isMandatory: true, // Mark as mandatory attribute field
      attributeMapping: {
        entity: 'main_entity',
        attribute: attr.name,
      },
      fieldMode: 'multi',
      ...(defaultValue ? { defaultValue: defaultValue.id || defaultValue.name } : {}),
    };
  });
};

/**
 * Convert FormBuilderData to backend FormSchemaDefinition format
 * @param values The form builder data
 * @returns The form schema definition for backend
 */
export const convertFormBuilderToSchema = (values: FormBuilderData): FormSchemaDefinition => {
  // Check if main entity is a container
  const isMainEntityContainer = CONTAINER_TYPES.includes(values.mainEntityType);

  return {
    version: '2.0',
    mainEntityType: values.mainEntityType,
    isContainer: isMainEntityContainer,
    mainEntityMultiple: values.mainEntityMultiple,
    mainEntityLookup: values.mainEntityLookup,
    additionalEntities: values.additionalEntities,
    fields: values.fields.map((field) => ({
      id: field.id,
      name: field.name,
      description: field.description,
      type: field.type,
      required: field.required,
      parseMode: field.parseMode,
      attributeMapping: field.attributeMapping,
      fieldMode: field.fieldMode,
      ...(field.defaultValue ? { defaultValue: field.defaultValue } : {}),
    })),
    relationships: values.relationships,
  };
};

// Helper to convert attribute type to field type for forms
const mapAttributeTypeToFieldType = (attrType: string): string => {
  if (attrType === 'date') return 'datetime';
  if (attrType === 'boolean') return 'checkbox';
  if (attrType === 'numeric' || attrType === 'integer' || attrType === 'float') return 'number';
  if (attrType === 'markdown' || attrType === 'text') return 'textarea';
  // Default to text for string and other types
  return 'text';
};

/**
 * Build entity types from schema with translations and attributes
 * @param schema The schema object from useAuth
 * @param entitySettings The entity settings from query with attributesDefinitions
 * @param t_i18n Translation function
 * @returns List of entity type options
 */
export const buildEntityTypes = (
  schema: any,
  entitySettings: any,
  t_i18n: (key: string) => string,
): EntityTypeOption[] => {
  const { sdos, scos, smos } = schema;

  // Create a map of entity settings for quick lookup
  const settingsMap = new Map<string, any>();
  entitySettings?.edges?.forEach(({ node }: any) => {
    if (node && 'target_type' in node) {
      settingsMap.set((node as any).target_type, node);
    }
  });

  const processEntityType = (s: any) => {
    const settings = settingsMap.get(s.id);

    // Use attributesDefinitions from the query which contains full attribute info
    const attributesDefinitions = settings?.attributesDefinitions || [];
    const mandatoryAttrs = settings?.mandatoryAttributes || [];
    
    // Map attributesDefinitions to the format expected by the form
    const attributes = attributesDefinitions.map((attr: any) => ({
      name: attr.name,
      label: attr.label || attr.name,
      type: attr.type,
      mandatory: attr.mandatory,
      mandatoryType: attr.mandatoryType,
      multiple: attr.multiple,
      scale: attr.scale,
      defaultValues: attr.defaultValues,
    }));

    return {
      value: s.id,
      label: t_i18n(`entity_${s.id}`),
      isContainer: s.isContainer || CONTAINER_TYPES.includes(s.id),
      attributes,
      mandatoryAttributes: mandatoryAttrs,
      defaultValuesAttributes: settings?.defaultValuesAttributes || [],
    };
  };

  const types = [
    ...sdos.map(processEntityType),
    ...scos.map(processEntityType),
    ...smos.map(processEntityType),
  ].sort((a, b) => a.label.localeCompare(b.label));

  return types;
};
