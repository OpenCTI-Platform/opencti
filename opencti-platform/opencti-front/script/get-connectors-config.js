import { compile } from 'json-schema-to-typescript';
import fs from 'fs/promises';
import path from 'path';
import _ from 'lodash';

const SCHEMA_URL = 'https://raw.githubusercontent.com/OpenCTI-Platform/connectors/refs/heads/oob/connector_manager/manifest.json'; // TODO set SCHEMA_URL in parameters
const OUTPUT_DIR = '__generated__/connectors';

async function getConnectorConfig() {
  try {
    console.log(`Fetching schema from ${SCHEMA_URL}...`);
    const response = await fetch(SCHEMA_URL);
    const data = await response.json();

    const connectorEntries = [];

    if (data.contracts) {
      console.log('Generating TypeScript interface...');
      await fs.mkdir(OUTPUT_DIR, { recursive: true });
      for (const connector of data.contracts) {
        const name = _.camelCase(connector.title);
        const type = _.upperFirst(name);
        const fileName = `${name}.d.ts`;

        const ts = await compile(connector, fileName);
        const outputPath = path.join(OUTPUT_DIR, fileName);
        await fs.writeFile(outputPath, ts);
        console.log(`✅ TypeScript interfaces written to ${outputPath}`);

        connectorEntries.push({ name, type });
      }

      const indexFilePath = path.join(OUTPUT_DIR, 'connectors.ts');
      const imports = connectorEntries
        .map(({ name, type }) => `import { ${type} } from './${name}';`)
        .join('\n');
      const connectorsObject = `export const openctiCatalog = {\n${connectorEntries
        .map(({ name, type }) => `  ${name}: {} as ${type},`)
        .join('\n')}\n};`;
      const fileContent = `${imports}\n\n${connectorsObject}\n`;
      await fs.writeFile(indexFilePath, fileContent);
      console.log(`✅ connectors.ts generated at ${indexFilePath}`);
    }

  } catch (e) {
    console.error('❌ Error:', e);
  }
}

await getConnectorConfig();
