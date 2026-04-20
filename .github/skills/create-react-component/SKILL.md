---
name: create-react-component
description: "Use when: creating a new Relay-connected React component, defining a GraphQL fragment, or wiring a component to a query"
---

# Create React Component (Relay)

## Prerequisites
- **Parent Component**: Knowing where this will be used.
- **Fragment**: The data requirements from GraphQL.

## Procedure

### Step 0 — Find an Existing Example
Use the **Codebase Pattern Finder** agent to locate a similar existing component in `opencti-platform/opencti-front/src/private/components/` that uses `useFragment`. Model the new component after the existing one to stay idiomatic.

### Step 1 — Create Component File
Location: `opencti-platform/opencti-front/src/private/components/...`.

### Step 2 — Define Fragment & Props
Use `graphql` tag and `useFragment`.

```tsx
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { MyComponent_data$key } from './__generated__/MyComponent_data.graphql';

const myComponentFragment = graphql`
  fragment MyComponent_data on EntityType {
    id
    name
    description
  }
`;

interface MyComponentProps {
  data: MyComponent_data$key;
}

const MyComponent: React.FC<MyComponentProps> = ({ data }) => {
  const node = useFragment(myComponentFragment, data);

  return (
    <div>
      <h1>{node.name}</h1>
      <p>{node.description}</p>
    </div>
  );
};

export default MyComponent;
```

### Step 3 — Run Relay Compiler
Run `yarn relay` to generate the TypeScript types.
