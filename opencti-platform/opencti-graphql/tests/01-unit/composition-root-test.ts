import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { printSchema } from 'graphql';
// Most of the src/back.ts import graph (src/boot needs the builder's migrations glob):
// registration must still be allowed once all of it is evaluated
import '../../src/manager/index';
import '../../src/managers';
import '../../src/http/httpServer';
import { MODULE_DESCRIPTORS, registerModules } from '../../src/composition-root';
import { schemaTypesDefinition } from '../../src/schema/schema-types';
import { schemaAttributesDefinition } from '../../src/schema/schema-attributes';
import { ABSTRACT_INTERNAL_OBJECT } from '../../src/schema/general';
import { ENTITY_TYPE_DATA_SANITY_EXECUTION } from '../../src/modules/dataSanity/dataSanity-types';
import createSchema from '../../src/graphql/schema';
import { modules } from '../../src/schema/module';
import { getAllDisabledManagers, getAllEnabledManagers } from '../../src/manager/managerModule';

const registeredManagerIds = () => [...getAllEnabledManagers(), ...getAllDisabledManagers()].map(({ manager }) => manager.id);

describe('Composition root', () => {
  it('should not register anything on import', () => {
    // Not through schemaTypesDefinition: reading it would lock the types before registerModules()
    expect(modules.has(ENTITY_TYPE_DATA_SANITY_EXECUTION)).toBe(false);
    expect(registeredManagerIds()).not.toContain('DATA_SANITY_MANAGER');
  });

  it('should register every part of a module descriptor', () => {
    registerModules();
    expect(MODULE_DESCRIPTORS.map(({ id }) => id)).toContain('dataSanity');
    expect(schemaTypesDefinition.get(ABSTRACT_INTERNAL_OBJECT)).toContain(ENTITY_TYPE_DATA_SANITY_EXECUTION);
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_DATA_SANITY_EXECUTION, 'operation_name')).toBeDefined();
    expect(printSchema(createSchema())).toContain('dataSanityOperations');
    expect(registeredManagerIds().filter((id) => id === 'DATA_SANITY_MANAGER')).toHaveLength(1);
  });

  it('should register only once', () => {
    registerModules();
    expect(registeredManagerIds().filter((id) => id === 'DATA_SANITY_MANAGER')).toHaveLength(1);
  });

  it('should refuse to register other descriptors once registered', () => {
    expect(() => registerModules(MODULE_DESCRIPTORS.slice(1))).toThrow('Modules are already registered with other descriptors');
    expect(() => registerModules([...MODULE_DESCRIPTORS].reverse())).toThrow('Modules are already registered with other descriptors');
  });

  it('should list every module descriptor', async () => {
    const modulesPath = join(__dirname, '../../src/modules');
    const descriptorFiles = readdirSync(modulesPath, { recursive: true, encoding: 'utf8' }).filter((file) => file.endsWith('-module.ts'));
    // Already evaluated through the composition root, except the unlisted ones: importing a descriptor has no side effect
    const descriptors = await Promise.all(descriptorFiles.map(async (file) => (await import(join(modulesPath, file))).default));
    expect(descriptorFiles.filter((_, index) => !MODULE_DESCRIPTORS.includes(descriptors[index]))).toEqual([]);
    expect(descriptorFiles).toHaveLength(MODULE_DESCRIPTORS.length);
  });
});
