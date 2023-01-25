import path from 'node:path';
import fastGlob from 'fast-glob';

const MIGRATIONS_IMPORT = 'import migrations, { filenames as migrationsFilenames } from \'../migrations/*.js\';'

function vitestMigrationPlugin(opts = {}) {
    return {
        name: 'glob',
        transform(code, id) {
            let newSourceCode = code;
            if (code.includes(MIGRATIONS_IMPORT)) {
                const files = fastGlob.sync('*.js', {cwd: path.dirname(id) + '/../migrations'}).sort();
                const importerCode = `${files.map((module, index) => `
                    import * as module${index} from '../migrations/${module}'`).join(';')}
                    const migrations = [${files.map((module, index) => `module${index}`).join(',')}];
                    export const migrationsFilenames = [${files.map((module, index) => `'${module}'`).join(',')}]
              `;
               newSourceCode = code.replace(MIGRATIONS_IMPORT, importerCode);
            }
            const map = { mappings: '' };
            return { code: newSourceCode, map }
        }
    };
}

export default vitestMigrationPlugin;