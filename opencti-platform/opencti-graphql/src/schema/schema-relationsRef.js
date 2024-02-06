import { getParentTypes } from './schemaUtils';
import { UnsupportedError } from '../config/errors';
import { STIX_CORE_RELATIONSHIPS } from './stixCoreRelationship';
let usageProtection = false;
export const schemaRelationsRefDefinition = {
    relationsRef: {},
    // allRelationsRef is a list of the names of all the relations ref registered in a schema definition
    allRelationsRef: [],
    namesCache: new Map(),
    stixNamesCache: new Map(),
    // Map
    databaseNameMultipleCache: new Map(),
    databaseNameToInputNameCache: new Map(),
    nameToDatabaseName: new Map(),
    stixNameToInputNameCache: new Map(),
    relationsRefCacheArray: new Map(),
    relationsRefCacheMap: new Map(),
    registerRelationsRef(entityType, relationsRefDefinition) {
        var _a;
        if (usageProtection) {
            throw UnsupportedError('Register relations refs use after usage, please check your imports');
        }
        const directRefs = (_a = this.relationsRef[entityType]) !== null && _a !== void 0 ? _a : new Map();
        // Register given relations ref
        relationsRefDefinition.forEach((relationRefDefinition) => {
            // Check name collision with STIX_CORE_RELATIONSHIP
            if (STIX_CORE_RELATIONSHIPS.includes(relationRefDefinition.name)) {
                throw UnsupportedError('You can\'t register a relations ref with an existing stix-core-relationship name', {
                    relationRef: relationRefDefinition.name
                });
            }
            // Check duplicate relations ref
            if (directRefs.has(relationRefDefinition.name)) {
                throw UnsupportedError('You can\'t register two relations ref with the same name on an entity', {
                    relationRef: relationRefDefinition.name,
                    entityType
                });
            }
            directRefs.set(relationRefDefinition.name, relationRefDefinition);
            if (!this.allRelationsRef.includes(relationRefDefinition.name)) {
                this.allRelationsRef.push(relationRefDefinition.name);
            }
        });
        this.relationsRef[entityType] = directRefs;
        // Register inheritance attributes
        const parentRefs = new Map(getParentTypes(entityType)
            .map((type) => { var _a; return Array.from(((_a = this.relationsRef[type]) !== null && _a !== void 0 ? _a : new Map()).values()); })
            .flat().map((e) => [e.name, e]));
        const computedWithParentsRefs = new Map([...parentRefs, ...directRefs]);
        this.relationsRefCacheMap.set(entityType, computedWithParentsRefs);
        // Generate cache map
        this.namesCache.set(entityType, Array.from(computedWithParentsRefs.keys()));
        const computedWithParentsRefsArray = Array.from(computedWithParentsRefs.values());
        this.relationsRefCacheArray.set(entityType, computedWithParentsRefsArray);
        this.stixNamesCache.set(entityType, computedWithParentsRefsArray.map((rel) => rel.stixName));
        this.databaseNameMultipleCache.set(entityType, computedWithParentsRefsArray.filter((rel) => rel.multiple).map((rel) => rel.databaseName));
        computedWithParentsRefsArray.forEach((ref) => this.nameToDatabaseName.set(ref.name, ref.databaseName));
        this.databaseNameToInputNameCache.set(entityType, new Map(computedWithParentsRefsArray.map((ref) => [ref.databaseName, ref.name])));
        this.stixNameToInputNameCache.set(entityType, new Map(computedWithParentsRefsArray.map((ref) => [ref.stixName, ref.name])));
    },
    selectEntityType(entityType) {
        usageProtection = true;
        if (this.relationsRefCacheMap.has(entityType)) {
            return entityType;
        }
        const types = [...getParentTypes(entityType)].reverse();
        for (let i = 0; i < types.length; i += 1) {
            const type = types[i];
            if (this.relationsRefCacheMap.has(type)) {
                return type;
            }
        }
        throw UnsupportedError('Register relations has no registration for type', { type: entityType });
    },
    getRelationsRef(entityType) {
        var _a;
        return (_a = this.relationsRefCacheArray.get(this.selectEntityType(entityType))) !== null && _a !== void 0 ? _a : [];
    },
    getRelationRef(entityType, name) {
        var _a, _b;
        return (_b = (_a = this.relationsRefCacheMap.get(this.selectEntityType(entityType))) === null || _a === void 0 ? void 0 : _a.get(name)) !== null && _b !== void 0 ? _b : null;
    },
    // relationsRefMap(entityType: string) {
    //   return new Map(schemaRelationsRefDefinition.getRelationsRef(entityType).map((n) => [n.name, n]));
    // },
    getInputNames(entityType) {
        var _a;
        return (_a = this.namesCache.get(this.selectEntityType(entityType))) !== null && _a !== void 0 ? _a : [];
    },
    getAllInputNames() {
        usageProtection = true;
        return this.allRelationsRef;
    },
    getStixNames(entityType) {
        var _a;
        return (_a = this.stixNamesCache.get(this.selectEntityType(entityType))) !== null && _a !== void 0 ? _a : [];
    },
    isMultipleDatabaseName(entityType, databaseName) {
        var _a, _b;
        return (_b = (_a = this.databaseNameMultipleCache.get(this.selectEntityType(entityType))) === null || _a === void 0 ? void 0 : _a.includes(databaseName)) !== null && _b !== void 0 ? _b : false;
    },
    convertDatabaseNameToInputName(entityType, databaseName) {
        var _a, _b;
        return (_b = (_a = this.databaseNameToInputNameCache.get(this.selectEntityType(entityType))) === null || _a === void 0 ? void 0 : _a.get(databaseName)) !== null && _b !== void 0 ? _b : null;
    },
    convertStixNameToInputName(entityType, stixName) {
        var _a, _b;
        return (_b = (_a = this.stixNameToInputNameCache.get(this.selectEntityType(entityType))) === null || _a === void 0 ? void 0 : _a.get(stixName)) !== null && _b !== void 0 ? _b : null;
    },
    isDatable(entityType, databaseName) {
        var _a;
        const name = this.convertDatabaseNameToInputName(entityType, databaseName);
        if (!name) {
            throw UnsupportedError('Relation Ref not found');
        }
        return (_a = this.getRelationRef(entityType, name)) === null || _a === void 0 ? void 0 : _a.datable;
    },
    getDatables() {
        usageProtection = true;
        return Array.from(this.relationsRefCacheArray.values()).flat()
            .filter((rel) => rel.datable)
            .map((rel) => rel.name);
    },
    getDatabaseName(name) {
        usageProtection = true;
        return this.nameToDatabaseName.get(name);
    },
    getAllDatabaseName() {
        usageProtection = true;
        return this.getAllInputNames()
            .map((name) => this.getDatabaseName(name))
            .filter((n) => n !== undefined);
    }
};
