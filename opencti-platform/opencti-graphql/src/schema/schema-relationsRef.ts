import type { RelationRefDefinition } from './relationRef-definition';
import { getParentTypes } from './schemaUtils';
import { UnsupportedError } from '../config/errors';
import { STIX_CORE_RELATIONSHIPS } from './stixCoreRelationship';

export const schemaRelationsRefDefinition = {
  relationsRef: {} as Record<string, Map<string, RelationRefDefinition>>,

  inputNamesCache: new Map<string, string[]>(),
  stixNamesCache: new Map<string, string[]>(),

  // Map
  databaseNameMultipleCache: new Map<string, string[]>(),

  databaseNameToInputNameCache: new Map<string, Map<string, string>>(),
  inputNameToDatabaseName: new Map<string, string>(),
  stixNameToInputNameCache: new Map<string, Map<string, string>>(),

  relationsRefCacheArray: new Map<string, RelationRefDefinition[]>(),
  relationsRefCacheMap: new Map<string, Map<string, RelationRefDefinition>>(),

  registerRelationsRef(entityType: string, relationsRefDefinition: RelationRefDefinition[]) {
    const directRefs = this.relationsRef[entityType] ?? new Map<string, RelationRefDefinition>();

    // Register given relations ref
    relationsRefDefinition.forEach((relationRefDefinition) => {
      // Check name collision with STIX_CORE_RELATIONSHIP
      if (STIX_CORE_RELATIONSHIPS.includes(relationRefDefinition.databaseName)) {
        throw UnsupportedError('You can\'t register a relations ref with an existing stix-core-relationship name', {
          relationRef: relationRefDefinition.databaseName
        });
      }

      // Check duplicate relations ref
      if (directRefs.has(relationRefDefinition.inputName)) {
        throw UnsupportedError('You can\'t register two relations ref with the same name on an entity', {
          relationRef: relationRefDefinition.inputName,
          entityType
        });
      }

      directRefs.set(relationRefDefinition.inputName, relationRefDefinition);
    });

    this.relationsRef[entityType] = directRefs;

    this.computeCache(entityType);
  },

  // Extract this method to be call in all methods
  // When an entity not register any relations, the relations for this entity is not computed
  // Call only in register mechanism when all the entities will be migrated
  computeCache(entityType: string) {
    if (this.relationsRefCacheMap.has(entityType)) return;

    const directRefs = this.relationsRef[entityType] ?? new Map();
    // Register inheritance attributes
    const parentRefs = new Map(
      getParentTypes(entityType)
        .map((type) => Array.from((this.relationsRef[type] ?? new Map()).values()))
        .flat()
        .map((e) => [e.inputName, e])
    );
    const computedWithParentsRefs = new Map([...parentRefs, ...directRefs]);
    this.relationsRefCacheMap.set(entityType, computedWithParentsRefs);

    // Generate cache map
    this.inputNamesCache.set(entityType, Array.from(computedWithParentsRefs.keys()));
    const computedWithParentsRefsArray = Array.from(computedWithParentsRefs.values());
    this.relationsRefCacheArray.set(entityType, computedWithParentsRefsArray);
    this.stixNamesCache.set(entityType, computedWithParentsRefsArray.map((rel) => rel.stixName));
    this.databaseNameMultipleCache.set(entityType, computedWithParentsRefsArray.filter((rel) => rel.multiple).map((rel) => rel.databaseName));
    computedWithParentsRefsArray.forEach((ref) => this.inputNameToDatabaseName.set(ref.inputName, ref.databaseName));
    this.databaseNameToInputNameCache.set(entityType, new Map(computedWithParentsRefsArray.map((ref) => [ref.databaseName, ref.inputName])));
    this.stixNameToInputNameCache.set(entityType, new Map(computedWithParentsRefsArray.map((ref) => [ref.stixName, ref.inputName])));
  },

  getRelationsRef(entityType: string): RelationRefDefinition[] {
    this.computeCache(entityType);
    return this.relationsRefCacheArray.get(entityType) ?? [];
  },

  getRelationRef(entityType: string, inputName: string): RelationRefDefinition | null {
    this.computeCache(entityType);
    return this.relationsRefCacheMap.get(entityType)?.get(inputName) ?? null;
  },

  relationsRefMap(entityType: string) {
    return new Map(schemaRelationsRefDefinition.getRelationsRef(entityType).map((n) => [n.stixName, n.label]));
  },

  getInputNames(entityType: string): string[] {
    this.computeCache(entityType);
    return this.inputNamesCache.get(entityType) ?? [];
  },

  getStixNames(entityType: string): string[] {
    this.computeCache(entityType);
    return this.stixNamesCache.get(entityType) ?? [];
  },

  isMultipleDatabaseName(entityType: string, databaseName: string): boolean {
    this.computeCache(entityType);
    return this.databaseNameMultipleCache.get(entityType)?.includes(databaseName) ?? false;
  },

  convertDatabaseNameToInputName(entityType: string, databaseName: string): string | null {
    this.computeCache(entityType);
    return this.databaseNameToInputNameCache.get(entityType)?.get(databaseName) ?? null;
  },

  convertStixNameToInputName(entityType: string, stixName: string): string | null {
    this.computeCache(entityType);
    return this.stixNameToInputNameCache.get(entityType)?.get(stixName) ?? null;
  },

  isDatable(entityType: string, databaseName: string) : boolean | undefined {
    const inputName = this.convertDatabaseNameToInputName(entityType, databaseName);
    if (!inputName) {
      throw UnsupportedError('Relation Ref not found');
    }
    return this.getRelationRef(entityType, inputName)?.datable;
  },

  getDatables() : string[] {
    return Array.from(this.relationsRefCacheArray.values()).flat()
      .filter((rel) => rel.datable)
      .map((rel) => rel.databaseName);
  },

  getDatabaseName(inputName: string, entityTypes?: string[]): string | undefined {
    if (entityTypes) {
      entityTypes.forEach((type) => this.computeCache(type));
    }
    return this.inputNameToDatabaseName.get(inputName);
  }
};
