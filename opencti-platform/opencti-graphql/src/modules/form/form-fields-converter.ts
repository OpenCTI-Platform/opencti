import { internalLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { FormFieldDefinition } from './form-types';
import { isEmptyField } from '../../database/utils';

// Helper function to convert string values to proper types based on field type
export const convertFieldType = (value: any, field: FormFieldDefinition): any => {
  // Don't convert if already the right type or if value is null/undefined
  if (isEmptyField(value)) {
    return value;
  }

  // Handle boolean fields
  if (field.type === 'checkbox' || field.type === 'toggle') {
    if (typeof value === 'string') {
      return value === 'true' || value === '1';
    }
    return Boolean(value);
  }

  // Handle number fields
  if (field.type === 'number') {
    if (typeof value === 'string') {
      const num = Number(value);
      return Number.isNaN(num) ? value : num;
    }
    return value;
  }

  // For other types, return as-is
  return value;
};

// Helper function to transform special fields for STIX conversion (entities and relationships)
export const transformSpecialFields = async (
  context: AuthContext,
  user: AuthUser,
  data: any,
  fields: FormFieldDefinition[],
  isRelationship: boolean = false,
): Promise<any> => {
  const transformed = { ...data };

  // For relationships, the field values come from the 'fields' property
  const fieldsSource = isRelationship && data.fields ? data.fields : data;

  // Find special fields that need transformation

  for (const field of fields) {
    const attrName = field.attributeMapping.attributeName;
    const value = (fieldsSource as any)[attrName];

    if (!value) {
      continue;
    }

    if (field.type === 'createdBy' && typeof value === 'string') {
      // Transform createdBy from internal_id
      const createdByEntity = await internalLoadById(context, user, value);
      if (createdByEntity) {
        if (isRelationship) {
          // For relationships, use STIX ref format
          transformed.created_by_ref = createdByEntity.standard_id;
        } else {
          // For entities, use object format
          (transformed as any).createdBy = {
            internal_id: createdByEntity.internal_id,
            standard_id: createdByEntity.standard_id,
          };
        }
      }
    } else if (field.type === 'objectMarking' && Array.isArray(value)) {
      // Transform objectMarking from array of internal_ids
      const markings = [];

      for (const markingId of value) {
        if (typeof markingId === 'string') {
          const markingEntity = await internalLoadById(context, user, markingId);
          if (markingEntity) {
            if (isRelationship) {
              // For relationships, just collect standard_ids
              markings.push(markingEntity.standard_id);
            } else {
              // For entities, use object format
              markings.push({
                internal_id: markingEntity.internal_id,
                standard_id: markingEntity.standard_id,
              });
            }
          }
        }
      }
      if (isRelationship) {
        transformed.object_marking_refs = markings;
      } else {
        (transformed as any).objectMarking = markings;
      }
    } else if (field.type === 'objectLabel' && Array.isArray(value)) {
      // Transform labels
      if (isRelationship) {
        transformed.labels = value; // For relationships, labels are simple strings
      } else {
        (transformed as any).objectLabel = value.map((label: any) => ({ value: label }));
      }
    } else if (field.type === 'files' && Array.isArray(value)) {
      // Transform files to x_opencti_files format
      // Files should come as array of { name: string, data: string } where data is base64 encoded
      const files = value.map((file: any) => ({
        name: file.name,
        data: file.data, // base64 encoded content
        mime_type: file.mime_type || 'application/octet-stream',
      }));
      if (!isRelationship) {
        (transformed as any).x_opencti_files = files;
      }
    } else if (field.type === 'externalReferences' && Array.isArray(value)) {
      // Transform external references
      const references = [];

      for (const refId of value) {
        if (typeof refId === 'string') {
          const refEntity = await internalLoadById(context, user, refId);
          if (refEntity) {
            references.push(refEntity);
          }
        }
      }
      (transformed as any).externalReferences = references;
    } else if (isRelationship && attrName && value !== undefined) {
      // For relationships, apply other fields directly
      transformed[attrName] = value;
    }
  }

  // For relationships, remove the fields object after processing
  if (isRelationship) {
    delete transformed.fields;
  }

  return transformed;
};
