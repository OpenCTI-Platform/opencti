import type { Checker, RelationRefDefinition } from './relationRef-definition';

export const schemaRelationsRefDefinition = {
  relationsRef: {} as Record<string, RelationRefDefinition[]>,

  inputName: [] as string[],
  databaseName: [] as string[],
  stixName: [] as string[],
  checker: {} as Record<string, Checker>,

  // Map
  databaseNameToStixName: {} as { [k: string]: string },
  stixNameToDatabaseName: {} as { [k: string]: string },

  databaseNameToInputName: {} as { [k: string]: string },
  inputNameToDatabaseName: {} as { [k: string]: string },

  stixNameToInputName: {} as { [k: string]: string },
  inputNameToStixName: {} as { [k: string]: string },

  registerRelationsRef(entityType: string, relationsRefDefinition: RelationRefDefinition[]) {
    this.relationsRef[entityType] = [...this.relationsRef[entityType] ?? [], ...relationsRefDefinition];

    relationsRefDefinition.forEach((relationRefDefinition) => {
      if (!this.getName().includes(relationRefDefinition.inputName)) {
        this.inputName.push(relationRefDefinition.inputName);
        this.databaseName.push(relationRefDefinition.databaseName);
        this.stixName.push(relationRefDefinition.stixName);
        if (relationRefDefinition.checker) {
          this.registerChecker(relationRefDefinition.databaseName, relationRefDefinition.checker);
        }

        this.databaseNameToStixName[relationRefDefinition.databaseName] = relationRefDefinition.stixName;
        this.stixNameToDatabaseName[relationRefDefinition.stixName] = relationRefDefinition.databaseName;

        this.databaseNameToInputName[relationRefDefinition.databaseName] = relationRefDefinition.inputName;
        this.inputNameToDatabaseName[relationRefDefinition.inputName] = relationRefDefinition.databaseName;

        this.stixNameToInputName[relationRefDefinition.stixName] = relationRefDefinition.inputName;
        this.inputNameToStixName[relationRefDefinition.inputName] = relationRefDefinition.stixName;
      }
    });
  },

  getRelationsRef(entityType: string): RelationRefDefinition[] {
    return this.relationsRef[entityType] ?? [];
  },

  registerChecker(databaseName: string, checker: Checker) {
    this.checker[databaseName] = checker;
  },

  getChecker(databaseName: string): Checker {
    return this.checker[databaseName];
  },

  getName(): string[] {
    return this.inputName;
  },

  getDatabaseName(): string[] {
    return this.databaseName;
  },

  isMultipleDatabaseName(databaseName: string): boolean {
    return Object.values(this.relationsRef ?? {}).flat()
      .find((rel) => rel.databaseName === databaseName)
      ?.multiple ?? false;
  },

  isMultipleName(name: string): boolean {
    return Object.values(this.relationsRef ?? {}).flat()
      .find((rel) => rel.inputName === name)
      ?.multiple ?? false;
  }
};
