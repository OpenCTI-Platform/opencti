import { isAbstract } from '../../schema/general';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';

/**
 * An attribute the schema declares as pointing to a User, and the entity types carrying it.
 *
 * `entityTypes` is undefined when the attribute is declared on an abstract root, which makes it
 * global: every document may carry it and no type filter is needed.
 */
export interface DiscoveredUserAttribute {
  name: string;
  multiple: boolean;
  entityTypes?: string[];
}

/**
 * Walks the schema type by type rather than through `getIdAttributes()`, which deduplicates by
 * attribute name and would collapse the several entities declaring `user_id` into one entry.
 */
export const discoverUserIdAttributes = (): DiscoveredUserAttribute[] => {
  const carriers = new Map<string, { multiple: boolean; entityTypes: string[]; global: boolean }>();
  schemaAttributesDefinition.getRegisteredTypes().forEach((entityType) => {
    const attributes = Array.from(schemaAttributesDefinition.getAttributes(entityType).values());
    attributes.forEach((attribute) => {
      if (attribute.type !== 'string' || attribute.format !== 'id') {
        return;
      }
      if (!(attribute.entityTypes ?? []).includes(ENTITY_TYPE_USER)) {
        return;
      }
      const carrier = carriers.get(attribute.name) ?? { multiple: attribute.multiple === true, entityTypes: [], global: false };
      if (isAbstract(entityType)) {
        carrier.global = true;
      } else if (!carrier.entityTypes.includes(entityType)) {
        carrier.entityTypes.push(entityType);
      }
      carriers.set(attribute.name, carrier);
    });
  });
  return Array.from(carriers.entries())
    .map(([name, carrier]) => ({ name, multiple: carrier.multiple, entityTypes: carrier.global ? undefined : carrier.entityTypes.sort() }))
    .sort((a, b) => a.name.localeCompare(b.name));
};
