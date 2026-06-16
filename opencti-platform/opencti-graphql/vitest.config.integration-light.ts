import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
import type { PluginOption } from 'vite';
import { BaseSequencer, type TestSpecification } from 'vitest/node';

export const buildIntegrationTestConfig = (include: string[]) => defineConfig({
  plugins: [graphql() as PluginOption],
  test: {
    dir: './tests',
    include,
    testTimeout: 1200000,
    teardownTimeout: 5000,
    setupFiles: ['./tests/setup/testSetup-light.js'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,js}'],
      exclude: ['src/generated/**', 'src/migrations/**', 'src/stixpattern/**', 'src/python/**'],
      reporter: ['text', 'json', 'html'],
      clean: false,
    },
    maxWorkers: 1,
    isolate: false,
    sequence: {
      shuffle: false,
      sequencer: class Sequencer extends BaseSequencer {
        async shard(files: TestSpecification[]) {
          return files;
        }

        async sort(files: TestSpecification[]) {
          return files.sort((testA, testB) => (testA.moduleId > testB.moduleId ? 1 : -1));
        }
      },
    },
  },
});

export default buildIntegrationTestConfig([
  '03-integration/01-database/filters-test.js',
]);

// ensuite : on met tous les nouveaux tests dans la version simplifiée
// créé et détruit les entités dans le test lui même
// regarder les diff de logs entre la CI de 13m et celle de 23m
// créer une page notion qui explique le brainstorm et qui donne des ETA => réaliser des chunks
// que faire avec les tests de sync qui dépendent aussi des création / délétion réalisées dans les tests
// utiliser des persistences séparés (containers ES distincts via docker ou testcontainers) sinon comment on vérifie combien on
// a d'entités à la fin du test => ou sinon rajouter des filtres
