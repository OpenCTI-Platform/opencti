import * as R from 'ramda';
import type { Checker, RelationRefDefinition } from './relationRef-definition';
import { getParentTypes } from './schemaUtils';

export const schemaRelationsRefDefinition = {
  relationsRef: {} as Record<string, RelationRefDefinition[]>,
  relationsRef_by_input: {} as Record<string, RelationRefDefinition>,

  inputNames: [] as string[],
  databaseNames: [] as string[],
  stixNames: [] as string[],
  checker: {} as Record<string, Checker>,

  // Map
  databaseNameMultiple: new Map<string, void>(),
  inputNameMultiple: new Map<string, void>(),

  databaseNameToInputName: {} as { [k: string]: string },
  inputNameToDatabaseName: {} as { [k: string]: string },

  stixNameToInputName: {} as { [k: string]: string },
  inputNameToStixName: {} as { [k: string]: string },

  relationsRefWithParentsCache: new Map<string, RelationRefDefinition[]>(),

  registerRelationsRef(entityType: string, relationsRefDefinition: RelationRefDefinition[]) {
    this.relationsRef[entityType] = [...this.relationsRef[entityType] ?? [], ...relationsRefDefinition];

    relationsRefDefinition.forEach((relationRefDefinition) => {
      if (!this.inputNames.includes(relationRefDefinition.inputName)) {
        this.inputNames.push(relationRefDefinition.inputName);
        this.databaseNames.push(relationRefDefinition.databaseName);
        this.stixNames.push(relationRefDefinition.stixName);
        if (relationRefDefinition.checker) {
          this.registerChecker(relationRefDefinition.databaseName, relationRefDefinition.checker);
        }
        if (relationRefDefinition.multiple) {
          this.databaseNameMultiple.set(relationRefDefinition.databaseName);
          this.inputNameMultiple.set(relationRefDefinition.inputName);
        }
        this.databaseNameToInputName[relationRefDefinition.databaseName] = relationRefDefinition.inputName;
        this.inputNameToDatabaseName[relationRefDefinition.inputName] = relationRefDefinition.databaseName;
        this.stixNameToInputName[relationRefDefinition.stixName] = relationRefDefinition.inputName;
        this.inputNameToStixName[relationRefDefinition.inputName] = relationRefDefinition.stixName;
        this.relationsRef_by_input[relationRefDefinition.inputName] = relationRefDefinition;
      }
    });
  },

  getRelationsRefByInputName(inputName: string): RelationRefDefinition {
    return this.relationsRef_by_input[inputName];
  },

  getRelationsRef(entityType: string): RelationRefDefinition[] {
    if (this.relationsRefWithParentsCache.has(entityType)) {
      return this.relationsRefWithParentsCache.get(entityType) ?? [];
    }
    const directRefs = R.fromPairs((this.relationsRef[entityType] ?? []).map((e) => [e.stixName, e]));
    const parentRefs = R.fromPairs(getParentTypes(entityType).map((type) => this.relationsRef[type] ?? [])
      .flat().map((e) => [e.stixName, e]));
    const computedWithParentsRefs = Object.values({ ...parentRefs, ...directRefs });
    this.relationsRefWithParentsCache.set(entityType, computedWithParentsRefs);
    return computedWithParentsRefs;
  },

  registerChecker(databaseName: string, checker: Checker) {
    this.checker[databaseName] = checker;
  },

  getChecker(databaseName: string): Checker {
    return this.checker[databaseName];
  },

  getInputNames(): string[] {
    return this.inputNames;
  },
  getDatabaseNames(): string[] {
    return this.databaseNames;
  },
  getStixNames(): string[] {
    return this.stixNames;
  },

  isMultipleDatabaseName(databaseName: string): boolean {
    return this.databaseNameMultiple.has(databaseName);
  },
  isMultipleName(name: string): boolean {
    return this.inputNameMultiple.has(name);
  },

  convertDatabaseNameToInputName(databaseName: string): string {
    return this.databaseNameToInputName[databaseName];
  },
  convertInputNameToDatabaseName(inputName: string): string {
    return this.inputNameToDatabaseName[inputName];
  },

  convertStixNameToInputName(stixName: string): string {
    return this.stixNameToInputName[stixName];
  },
  convertInputNameToStixName(inputName: string): string {
    return this.inputNameToStixName[inputName];
  }
};
