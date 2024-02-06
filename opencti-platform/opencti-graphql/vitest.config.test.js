var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
export const buildTestConfig = (include) => defineConfig({
    plugins: [graphql()],
    test: {
        include,
        testTimeout: 1200000,
        teardownTimeout: 20000,
        globalSetup: ['./tests/utils/globalSetup.js'],
        setupFiles: ['./tests/utils/testSetup.js'],
        coverage: {
            provider: 'v8',
            include: ['src/**'],
            exclude: ['src/generated/**', 'src/migrations/**', 'src/stixpattern/**', 'src/python/**'],
            reporter: ['text', 'json', 'html'],
        },
        poolOptions: {
            threads: {
                singleThread: true
            }
        },
        sequence: {
            shuffle: false,
            sequencer: class Sequencer {
                // eslint-disable-next-line class-methods-use-this
                shard(files) {
                    return __awaiter(this, void 0, void 0, function* () {
                        return files;
                    });
                }
                // eslint-disable-next-line class-methods-use-this
                sort(files) {
                    return __awaiter(this, void 0, void 0, function* () {
                        return files.sort((testA, testB) => (testA > testB ? 1 : -1));
                    });
                }
            },
        },
    },
});
export default buildTestConfig(['tests/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
// export default buildTestConfig(['tests/(02)-*/**/(loader|filterGroup|workspace)*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
