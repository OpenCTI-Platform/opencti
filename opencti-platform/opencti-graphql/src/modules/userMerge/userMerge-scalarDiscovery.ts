import { UnsupportedError } from '../../config/errors';
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
 *
 * A name carried by several entity types yields a single carrier, so those types have to agree
 * on the cardinality: it is what decides the rewrite script downstream, and picking the first
 * declaration seen would silently rewrite one of the types with the wrong one.
 */
export const discoverUserIdAttributes = (): DiscoveredUserAttribute[] => {
  const carriers = new Map<string, { multiple: boolean; declaredBy: string; entityTypes: string[]; global: boolean }>();
  schemaAttributesDefinition.getRegisteredTypes().forEach((entityType) => {
    const attributes = Array.from(schemaAttributesDefinition.getAttributes(entityType).values());
    attributes.forEach((attribute) => {
      if (attribute.type !== 'string' || attribute.format !== 'id') {
        return;
      }
      if (!(attribute.entityTypes ?? []).includes(ENTITY_TYPE_USER)) {
        return;
      }
      const multiple = attribute.multiple === true;
      const carrier = carriers.get(attribute.name) ?? { multiple, declaredBy: entityType, entityTypes: [], global: false };
      if (carrier.multiple !== multiple) {
        throw UnsupportedError('User reference attribute is declared with conflicting cardinalities', {
          attribute: attribute.name,
          declarations: [
            { entity_type: carrier.declaredBy, multiple: carrier.multiple },
            { entity_type: entityType, multiple },
          ],
        });
      }
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
