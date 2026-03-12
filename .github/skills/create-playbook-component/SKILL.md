# Create Playbook Component

## Prerequisites
- **Component ID**: Unique uppercase ID (e.g., `PLAYBOOK_MY_COMPONENT`).
- **Configuration**: List of fields required from the user.

## Procedure

### Step 1 — Create Component File
Location: `opencti-platform/opencti-graphql/src/modules/playbook/components/<name>-component.ts`.

### Step 2 — Define Configuration Schema
Define a TypeScript interface for the config and a JSONSchema for validation.

```typescript
export interface MyComponentConfig {
  key: string;
}

const SCHEMA: JSONSchemaType<MyComponentConfig> = {
  type: 'object',
  properties: {
    key: { type: 'string' },
  },
  required: ['key'],
};
```

### Step 3 — Implement Component Interface
Implement `PlaybookComponent<MyComponentConfig>`.

```typescript
export const PLAYBOOK_MY_COMPONENT: PlaybookComponent<MyComponentConfig> = {
  id: 'PLAYBOOK_MY_COMPONENT',
  name: 'My Component',
  description: 'Does something useful',
  icon: 'icon-name',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: SCHEMA,
  schema: async () => SCHEMA,
  executor: async ({ bundle, playbookNode }) => {
    // Business logic here
    const config = playbookNode.configuration;
    
    return { output_port: 'out', bundle };
  },
};
```

### Step 4 — Register Component
Import and add to `PLAYBOOK_COMPONENTS` in `src/modules/playbook/playbook-components.ts`.
