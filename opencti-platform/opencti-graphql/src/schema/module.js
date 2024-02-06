import { stixCoreRelationshipsMapping as coreRels } from '../database/stix';
import { registerStixDomainConverter, registerStixMetaConverter, registerStixRepresentativeConverter } from '../database/stix-converter';
// import { registerGraphqlSchema } from '../graphql/schema';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_META_OBJECT, ABSTRACT_STIX_REF_RELATIONSHIP, ENTITY_TYPE_CONTAINER, ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION, ENTITY_TYPE_THREAT_ACTOR, } from './general';
import { UnsupportedError } from '../config/errors';
import { iAliasedIds, standardId } from './attribute-definition';
import { depsKeysRegister, schemaAttributesDefinition } from './schema-attributes';
import { STIX_CORE_RELATIONSHIPS } from './stixCoreRelationship';
import { registerEntityValidator } from './validator-register';
import { schemaRelationsRefDefinition } from './schema-relationsRef';
import { registerStixDomainAliased, resolveAliasesField } from './stixDomainObject';
import { registerModelIdentifier } from './identifier';
import { schemaTypesDefinition } from './schema-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
export const registerDefinition = (definition) => {
    var _a;
    // Register types
    if (definition.type.category) {
        switch (definition.type.category) {
            case ENTITY_TYPE_THREAT_ACTOR:
                schemaTypesDefinition.add(ENTITY_TYPE_THREAT_ACTOR, definition.type.name);
                schemaTypesDefinition.add(ABSTRACT_STIX_DOMAIN_OBJECT, definition.type.name);
                registerStixDomainConverter(definition.type.name, definition.converter);
                break;
            case ENTITY_TYPE_LOCATION:
                schemaTypesDefinition.add(ENTITY_TYPE_LOCATION, definition.type.name);
                schemaTypesDefinition.add(ABSTRACT_STIX_DOMAIN_OBJECT, definition.type.name);
                registerStixDomainConverter(definition.type.name, definition.converter);
                break;
            case ENTITY_TYPE_CONTAINER:
                schemaTypesDefinition.add(ENTITY_TYPE_CONTAINER, definition.type.name);
                // Hack to handle Case, a feature has been created to fix it :)
                if (definition.type.name !== ENTITY_TYPE_CONTAINER_CASE) {
                    schemaTypesDefinition.add(ABSTRACT_STIX_DOMAIN_OBJECT, definition.type.name);
                    registerStixDomainConverter(definition.type.name, definition.converter);
                }
                break;
            case ENTITY_TYPE_CONTAINER_CASE:
                schemaTypesDefinition.add(ENTITY_TYPE_CONTAINER_CASE, definition.type.name);
                schemaTypesDefinition.add(ENTITY_TYPE_CONTAINER, definition.type.name);
                schemaTypesDefinition.add(ABSTRACT_STIX_DOMAIN_OBJECT, definition.type.name);
                registerStixDomainConverter(definition.type.name, definition.converter);
                break;
            case ENTITY_TYPE_IDENTITY:
                schemaTypesDefinition.add(ENTITY_TYPE_IDENTITY, definition.type.name);
                schemaTypesDefinition.add(ABSTRACT_STIX_DOMAIN_OBJECT, definition.type.name);
                registerStixDomainConverter(definition.type.name, definition.converter);
                break;
            case ABSTRACT_STIX_DOMAIN_OBJECT:
                schemaTypesDefinition.add(ABSTRACT_STIX_DOMAIN_OBJECT, definition.type.name);
                registerStixDomainConverter(definition.type.name, definition.converter);
                break;
            case ABSTRACT_STIX_META_OBJECT:
                schemaTypesDefinition.add(ABSTRACT_STIX_META_OBJECT, definition.type.name);
                registerStixMetaConverter(definition.type.name, definition.converter);
                break;
            case ABSTRACT_INTERNAL_OBJECT:
                schemaTypesDefinition.add(ABSTRACT_INTERNAL_OBJECT, definition.type.name);
                break;
            default:
                throw UnsupportedError('Unsupported category');
        }
        if (definition.type.aliased) {
            registerStixDomainAliased(definition.type.name);
        }
    }
    // Register representative
    registerStixRepresentativeConverter(definition.type.name, definition.representative);
    // Register validator
    if (definition.validators) {
        registerEntityValidator(definition.type.name, definition.validators);
    }
    // Register key identification
    registerModelIdentifier(definition.identifier);
    // Register model attributes
    const attributes = [standardId];
    attributes.push(...definition.attributes.map((attr) => attr));
    if (definition.type.aliased) {
        attributes.push(...[resolveAliasesField(definition.type.name), iAliasedIds]);
    }
    schemaAttributesDefinition.registerAttributes(definition.type.name, attributes);
    // Register dependency keys for input resolved refs
    if (definition.depsKeys) {
        depsKeysRegister.add(definition.depsKeys);
    }
    // Register relations
    definition.relations.forEach((source) => {
        STIX_CORE_RELATIONSHIPS.push(source.name);
        source.targets.forEach((target) => {
            var _a;
            const key = `${definition.type.name}_${target.name}`;
            coreRels[key] = [...((_a = coreRels[key]) !== null && _a !== void 0 ? _a : []), { name: source.name, type: target.type }];
        });
    });
    // Register relations ref
    schemaRelationsRefDefinition.registerRelationsRef(definition.type.name, definition.relationsRefs || []);
    (_a = definition.relationsRefs) === null || _a === void 0 ? void 0 : _a.forEach((source) => {
        schemaTypesDefinition.add(ABSTRACT_STIX_REF_RELATIONSHIP, source.databaseName);
    });
};
