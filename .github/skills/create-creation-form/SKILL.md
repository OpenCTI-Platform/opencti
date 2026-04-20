---
name: create-creation-form
description: "Use when: scaffolding a creation form drawer with Formik validation and a Relay mutation for a new entity"
---

# Create Creation Form (Drawer)

## Prerequisites
- **Mutation**: GraphQL mutation for creating the entity.
- **Fields**: List of fields to display.

## Procedure

### Step 0 — Find an Existing Example
Use the **Codebase Pattern Finder** agent to locate a similar existing creation form in `opencti-platform/opencti-front/src/private/components/` (look for files ending in `Creation.tsx`). Model the new form after the existing one to stay idiomatic.

### Step 1 — Define Mutation & Validation
Use `Yup` for validation schema.

```tsx
const creationMutation = graphql`
  mutation MyEntityCreationMutation($input: MyEntityAddInput!) {
    myEntityAdd(input: $input) {
      ...MyEntityLine_node
    }
  }
`;

const validationSchema = Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
});
```

### Step 2 — Create Component Structure
Return a `Drawer` containing a `Formik` form.

```tsx
export const MyEntityCreation: React.FC<Props> = ({ paginationOptions }) => {
  const [commit] = useApiMutation(creationMutation);
  
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    commit({
      variables: {
        input: values,
      },
      updater: (store) => {
        // Use utils/store helper
        insertNode(store, 'Pagination_myEntities', paginationOptions, 'myEntityAdd');
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Drawer title={t('Create entity')}>
      <Formik initialValues={{ name: '' }} validationSchema={validationSchema} onSubmit={onSubmit}>
         <Form>
            <Field component={TextField} name="name" label={t('Name')} />
             <Button type="submit">{t('Create')}</Button>
         </Form>
      </Formik>
    </Drawer>
  );
};
```
