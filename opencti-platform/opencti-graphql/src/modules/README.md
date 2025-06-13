# To create a module

1. Based on a sample directory as 'Channel', create the new module directory
2. Modify `graphql-codegen.yml` to add the mapper for the type
3. Register the module in `./index.ts`
4. Add new types in union (2) the main `opencti.graphql` file for types:
   - `StixCoreObjectOrStixCoreRelationship`
   - `StixObjectOrStixRelationship`
   - `StixObjectOrStixRelationshipOrCreator`
5. Adapt the new module files:
   - ## GraphQL schema
   starts with its own **GraphQL schema** model definition: 
      → `opencti-graphql/src/modules/newEntityName/newEntityName.graphql`
   This file will contains all the definition of the api schema (Entity, mutation, queries)
   
   - ## Module resolver
   is the bridge between the schema and the code :
      → `opencti-graphql/src/modules/newEntityName/newEntityName-resolver.ts`
   The resolver will contains all the query and mutation required by the schema. Resolver will not really contains business intelligence.
   
   - ## Module domain
   in order to not directly put business code in the resolvers we use the concept of **domain**:
     → `opencti-graphql/src/modules/newEntityName/newEntityName-domain.ts`
   Domain will be called by the resolver and use all the capability of the engine to do his job. 
   A lot of features are already available and so have just to be called by the domain. If its not the case, the domain can do some business intelligence.
   
   - ## Module types 
   define the different model types for the module object
     → `opencti-graphql/src/modules/newEntityName/newEntityName-types.ts`.
   
   - ## Module model converter
   convert the internal format (Store) to the STIX model for external and internal usage
     → `opencti-graphql/src/modules/newEntityName/newEntityName-converter.ts`
   
   - ## Module definition
   Finally the module must declare all the associated behaviors
     → `opencti-graphql/src/modules/newEntityName/newEntityName.ts`. 
   This file is responsible to define and register a `ModuleDefinition.`
   This definition will define what is your module and give all information needed by the engine to correctly process your module.
      
      - `type` → What kind of type is your module, is it aliased or not, etc.
         - Each category contains all the underlying types, representing the hierarchy.
        - `graphql`→ Where is the schema and the associated resolver
        - `identifier`→ On what elements the internal standard key will be generated
        - `representative` → A method to convert the entity in a representative way for a notification
        - `converter` → A method to convert the entity in a stix format
        - `attributes`→ The specific attributes that your module have. Defining some type and behavior to help the engine applying restriction and correct behavior.
        - `relations`→ The list of authorized relationships for your element.
        - `relationsRefs`→ The list of authorized relationships ref for your element.
        - `validators` → Methods to validate the entity in create and update mechanism and used in [Data workflow validation](https://www.notion.so/Data-workflow-validation-cdacabae2c8641f0990c1ccc42648da4?pvs=21)
      
      ### Attributes
      
      All the attributes of your entity, going through the API, must be defined to be handle properly by the back-end.
      
      This must be defined regarding this schema :
      
      - `name` → name of the attributes
        - `type` → type of the attribute
          depending on  type, other fields might be required, for instance the `values`  for `enum` type
        - `mandatoryType` → if the attribute is mandatory in `internal` (needed to be handle in the back-end), in `external` (GraphQL schema), could be `customizable` (made mandatory by a front-end user), or `no`
        - `multiple` → can contain an array of values
        - `upsert` → can be upsertable (different of updatable)
        - `label` → a label for the front-end
        - `description` → a description for the front-end
        - `isFilterable` → can be filtered in api calls using name as filter key
        - `schemaDef` → a JSON schema definition, used if the attribute is a JSON type to validate his schema in [Data workflow validation](https://www.notion.so/Data-workflow-validation-cdacabae2c8641f0990c1ccc42648da4?pvs=21)
           - For now, we handle JSON attribute by passing a string (`JSON.stringify`) instead of a JSON object. This allows us to take advantage of the existing generic PATCH method.
      
      ### Relations references
      
      All the relations refs of your entity, going through the API, must be defined to be handle properly by the back-end.
      
      This must be defined regarding this schema :
      - `inputName` → name of the relation in the GraphQL schema
        - `databaseName` → name of the relation in the database
        - `stixName` → name of the relation in the standard Stix
        - `mandatoryType` → if the attribute is mandatory in internal (needed to be handle in the back-end), in external (GraphQL schema), could be customizable (made mandatory by a front-end user), or no
        - `multiple` → can contain an array of values
        - `checker` → validate the consistency of the relation
        - `label` → a label for the front-end
        - `description` → a description for the front-end
        

