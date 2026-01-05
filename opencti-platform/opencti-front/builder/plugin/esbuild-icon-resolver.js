const { promises } = require("fs");

module.exports.IconResolverPlugin = {
  name: "icon-swapper-plugin",
  setup: (build) => {
    build.onLoad(
      { filter: /\.(js|jsx|ts|tsx)$/, namespace: "file" },
      async (args) => {
        let contents = await promises.readFile(args.path, "utf8");

        // Only process files that import MUI or MDI icons
        if (
          !contents.includes("@mui/icons-material") &&
          !contents.includes("mdi-material-ui")
        ) {
          return null;
        }

        let result = contents;

        // Handle named imports: import { Icon } from '@mui/icons-material'
        const muiNamedRegex =
          /import\s*\{([^}]+)\}\s*from\s*['"]@mui\/icons-material['"]/g;
        result = result.replace(muiNamedRegex, (fullMatch, importsString) => {
          const icons = importsString.split(",").map((s) => s.trim());
          return `import { ${icons.join(
            ", "
          )} } from 'src/icon-bridge/mui-icons-mapping'`;
        });

        // Handle default imports: import IconName from '@mui/icons-material/IconName'
        const muiDefaultRegex =
          /import\s+(\w+)\s+from\s*['"]@mui\/icons-material\/(\w+)['"]/g;
        result = result.replace(
          muiDefaultRegex,
          (fullMatch, localName, iconName) => {
            return `import { ${iconName} as ${localName} } from 'src/icon-bridge/mui-icons-mapping'`;
          }
        );

        // Handle named imports: import { Icon } from 'mdi-material-ui'
        const mdiNamedRegex =
          /import\s*\{([^}]+)\}\s*from\s*['"]mdi-material-ui['"]/g;
        result = result.replace(mdiNamedRegex, (fullMatch, importsString) => {
          const icons = importsString.split(",").map((s) => s.trim());
          return `import { ${icons.join(
            ", "
          )} } from 'src/icon-bridge/mdi-icons-mapping'`;
        });

        // Handle default imports: import IconName from 'mdi-material-ui/IconName'
        const mdiDefaultRegex =
          /import\s+(\w+)\s+from\s*['"]mdi-material-ui\/(\w+)['"]/g;
        result = result.replace(
          mdiDefaultRegex,
          (fullMatch, localName, iconName) => {
            return `import { ${iconName} as ${localName} } from 'src/icon-bridge/mdi-icons-mapping'`;
          }
        );

        // Only return modified contents if changes were made
        if (result !== contents) {
          return {
            contents: result,
            loader: "default",
          };
        }

        return null;
      }
    );
  },
};
