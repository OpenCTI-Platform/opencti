# Create React Component (Relay)

## Prerequisites
- **Parent Component**: Knowing where this will be used.
- **Fragment**: The data requirements from GraphQL.

## Procedure

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
