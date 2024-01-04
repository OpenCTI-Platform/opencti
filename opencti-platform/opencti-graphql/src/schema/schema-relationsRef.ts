import { getParentTypes } from './schemaUtils';
import { UnsupportedError } from '../config/errors';
import { STIX_CORE_RELATIONSHIPS } from './stixCoreRelationship';
import type { RefAttribute } from './attribute-definition';

let usageProtection = false;
export const schemaRelationsRefDefinition = {
  relationsRef: {} as Record<string, Map<string, RefAttribute>>,
  // allRelationsRef is a list of the names of all the relations ref registered in a schema definition
  allRelationsRef: [] as string[],

  namesCache: new Map<string, string[]>(),
  stixNamesCache: new Map<string, string[]>(),

  // Map
  databaseNameMultipleCache: new Map<string, string[]>(),

  databaseNameToInputNameCache: new Map<string, Map<string, string>>(),
  nameToDatabaseName: new Map<string, string>(),
  stixNameToInputNameCache: new Map<string, Map<string, string>>(),

  relationsRefCacheArray: new Map<string, RefAttribute[]>(),
  relationsRefCacheMap: new Map<string, Map<string, RefAttribute>>(),

  registerRelationsRef(entityType: string, relationsRefDefinition: RefAttribute[]) {
    if (usageProtection) {
      throw UnsupportedError('Register relations refs use after usage, please check your imports');
    }
    const directRefs = this.relationsRef[entityType] ?? new Map<string, RefAttribute>();
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
      .map((type) => Array.from((this.relationsRef[type] ?? new Map()).values()))
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

  selectEntityType(entityType: string) {
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

  getRelationsRef(entityType: string): RefAttribute[] {
    return this.relationsRefCacheArray.get(this.selectEntityType(entityType)) ?? [];
  },

  getRelationRef(entityType: string, name: string): RefAttribute | null {
    return this.relationsRefCacheMap.get(this.selectEntityType(entityType))?.get(name) ?? null;
  },

  // relationsRefMap(entityType: string) {
  //   return new Map(schemaRelationsRefDefinition.getRelationsRef(entityType).map((n) => [n.name, n]));
  // },

  getInputNames(entityType: string): string[] {
    return this.namesCache.get(this.selectEntityType(entityType)) ?? [];
  },

  getAllInputNames(): string[] {
    usageProtection = true;
    return this.allRelationsRef;
  },

  getStixNames(entityType: string): string[] {
    return this.stixNamesCache.get(this.selectEntityType(entityType)) ?? [];
  },

  isMultipleDatabaseName(entityType: string, databaseName: string): boolean {
    return this.databaseNameMultipleCache.get(this.selectEntityType(entityType))?.includes(databaseName) ?? false;
  },

  convertDatabaseNameToInputName(entityType: string, databaseName: string): string | null {
    return this.databaseNameToInputNameCache.get(this.selectEntityType(entityType))?.get(databaseName) ?? null;
  },

  convertStixNameToInputName(entityType: string, stixName: string): string | null {
    return this.stixNameToInputNameCache.get(this.selectEntityType(entityType))?.get(stixName) ?? null;
  },

  isDatable(entityType: string, databaseName: string) : boolean | undefined {
    const name = this.convertDatabaseNameToInputName(entityType, databaseName);
    if (!name) {
      throw UnsupportedError('Relation Ref not found');
    }
    return this.getRelationRef(entityType, name)?.datable;
  },

  getDatables() : string[] {
    usageProtection = true;
    return Array.from(this.relationsRefCacheArray.values()).flat()
      .filter((rel) => rel.datable)
      .map((rel) => rel.name);
  },

  getDatabaseName(name: string): string | undefined {
    usageProtection = true;
    return this.nameToDatabaseName.get(name);
  },

  getAllDatabaseName(): string[] {
    usageProtection = true;
    return this.getAllInputNames()
      .map((name) => this.getDatabaseName(name))
      .filter((n) => n !== undefined) as string[];
  }
};
