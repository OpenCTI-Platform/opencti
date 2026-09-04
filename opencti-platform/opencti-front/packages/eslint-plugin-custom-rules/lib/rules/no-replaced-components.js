import path from 'node:path';

// Fully replaced components: their Filigran Design System equivalent completely
// supersedes the MUI / legacy `@filigran/ui` version, so using the old one is an
// ERROR (unlike `no-deprecated-components`, which only warns). Identifiers are
// grouped by their DS replacement. Navbar / NavbarItem / NavbarSubmenu have no
// MUI counterpart in COMPONENT-MAPPING.md; they are kept here so that any legacy
// `@filigran/ui` import of them is still caught.
const REPLACED_COMPONENTS = {
  Breadcrumbs: 'Breadcrumbs',
  Breadcrumb: 'Breadcrumbs',
  BreadcrumbItem: 'Breadcrumbs',
  BreadcrumbLink: 'Breadcrumbs',
  BreadcrumbList: 'Breadcrumbs',
  BreadcrumbSeparator: 'Breadcrumbs',
  Navbar: 'Navbar',
  NavbarItem: 'NavbarItem',
  NavbarSubmenu: 'NavbarSubmenu',
};

// Same import sources the MUI regression gate watches
// (fds-migration/scripts/check-mui-regression.mjs).
const REPLACED_SOURCE_RE = /^@mui\/|^@filigran\/ui(\/|$)/;

const rule = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Disallow using components fully replaced by their Filigran Design System equivalent (see fds-migration/COMPONENT-MAPPING.md)',
    },
    schema: [],
    messages: {
      replaced: '`{{ identifier }}` is fully replaced by the Filigran Design System `{{ replacement }}` from \'@filigran/design-system\'; use it instead. See fds-migration/COMPONENT-MAPPING.md.',
    },
  },
  create: (context) => {
    return {
      ImportDeclaration(node) {
        const source = node.source.value;
        if (typeof source !== 'string' || !REPLACED_SOURCE_RE.test(source)) {
          return;
        }
        for (const specifier of node.specifiers) {
          let identifier = null;
          if (specifier.type === 'ImportSpecifier') {
            identifier = specifier.imported.name;
          } else if (specifier.type === 'ImportDefaultSpecifier') {
            // A default import carries no symbol name at the source, so the
            // module's own last path segment is the component:
            // '@mui/material/Paper' -> Paper.
            identifier = path.posix.basename(source);
          }
          if (identifier && Object.prototype.hasOwnProperty.call(REPLACED_COMPONENTS, identifier)) {
            context.report({
              node: specifier,
              messageId: 'replaced',
              data: {
                identifier,
                replacement: REPLACED_COMPONENTS[identifier],
              },
            });
          }
        }
      },
    };
  },
};

export default rule;
