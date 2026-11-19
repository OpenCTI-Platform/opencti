import { UnsupportedError } from '../../config/errors';
import { isAbstract } from '../../schema/general';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AttributeDefinition, MappingDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';

/**
 * An attribute the schema declares as pointing to a User, and the entity types carrying it.
 *
 * `name` is the dotted path of the attribute from the document root: a plain attribute name
 * at the top level, `<object>.<attribute>` for a field held inside an object attribute.
 *
 * `entityTypes` is undefined when the attribute is declared on an abstract root, which makes it
 * global: every document may carry it and no type filter is needed.
 */
export interface DiscoveredUserAttribute {
  name: string;
  multiple: boolean;
  entityTypes?: string[];
  /** Path of the outermost `nested` object holding the attribute, if any. */
  nestedRoot?: string;
  /** Path of the outermost object array (`multiple: true` object) holding the attribute, if any. */
  arrayRoot?: string;
}

interface UserReferenceAtPath {
  path: string;
  multiple: boolean;
  nestedRoot?: string;
  arrayRoot?: string;
}

const isUserReference = (attribute: AttributeDefinition | MappingDefinition): boolean => {
  return attribute.type === 'string' && attribute.format === 'id' && (attribute.entityTypes ?? []).includes(ENTITY_TYPE_USER);
};

/**
 * Yields every user reference reachable from an attribute, walking into the mappings of the
 * object attributes ('standard' and 'nested') so a field held inside an object is found the same
 * way as a top-level one. 'flat' and 'raw' objects declare no typed mapping and are not walked.
 */
const collectUserReferences = (
  attribute: AttributeDefinition | MappingDefinition,
  parentPath: string | undefined,
  nestedRoot: string | undefined,
  arrayRoot: string | undefined,
): UserReferenceAtPath[] => {
  const path = parentPath ? `${parentPath}.${attribute.name}` : attribute.name;
  if (isUserReference(attribute)) {
    return [{ path, multiple: attribute.multiple === true, nestedRoot, arrayRoot }];
  }
  if (attribute.type !== 'object' || (attribute.format !== 'standard' && attribute.format !== 'nested')) {
    return [];
  }
  const childNestedRoot = nestedRoot ?? (attribute.format === 'nested' ? path : undefined);
  const childArrayRoot = arrayRoot ?? (attribute.multiple ? path : undefined);
  return attribute.mappings.flatMap((mapping) => collectUserReferences(mapping, path, childNestedRoot, childArrayRoot));
};

/**
 * Walks the schema type by type rather than through `getIdAttributes()`, which deduplicates by
 * attribute name and would collapse the several entities declaring `user_id` into one entry.
 *
 * A path carried by several entity types yields a single carrier, so those types have to agree
 * on the cardinality: it is what decides the rewrite script downstream, and picking the first
 * declaration seen would silently rewrite one of the types with the wrong one.
 */
export const discoverUserIdAttributes = (): DiscoveredUserAttribute[] => {
  const carriers = new Map<string, { reference: UserReferenceAtPath; declaredBy: string; entityTypes: string[]; global: boolean }>();
  schemaAttributesDefinition.getRegisteredTypes().forEach((entityType) => {
    const attributes = Array.from(schemaAttributesDefinition.getAttributes(entityType).values());
    attributes.flatMap((attribute) => collectUserReferences(attribute, undefined, undefined, undefined)).forEach((reference) => {
      const carrier = carriers.get(reference.path) ?? { reference, declaredBy: entityType, entityTypes: [], global: false };
      if (carrier.reference.multiple !== reference.multiple) {
        throw UnsupportedError('User reference attribute is declared with conflicting cardinalities', {
          attribute: reference.path,
          declarations: [
            { entity_type: carrier.declaredBy, multiple: carrier.reference.multiple },
            { entity_type: entityType, multiple: reference.multiple },
          ],
        });
      }
      if (isAbstract(entityType)) {
        carrier.global = true;
      } else if (!carrier.entityTypes.includes(entityType)) {
        carrier.entityTypes.push(entityType);
      }
      carriers.set(reference.path, carrier);
    });
  });
  return Array.from(carriers.entries())
    .map(([name, carrier]) => {
      const discovered: DiscoveredUserAttribute = {
        name,
        multiple: carrier.reference.multiple,
        entityTypes: carrier.global ? undefined : carrier.entityTypes.sort(),
      };
      if (carrier.reference.nestedRoot) {
        discovered.nestedRoot = carrier.reference.nestedRoot;
      }
      if (carrier.reference.arrayRoot) {
        discovered.arrayRoot = carrier.reference.arrayRoot;
      }
      return discovered;
    })
    .sort((a, b) => a.name.localeCompare(b.name));
};
