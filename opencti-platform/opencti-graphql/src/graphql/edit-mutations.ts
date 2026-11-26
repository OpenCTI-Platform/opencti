import type { Resolvers, ResolversTypes } from '../generated/graphql';

// The keys a generated type declares, without the index signature ResolversObject adds.
type DeclaredKeys<T> = keyof { [Key in keyof T as string extends Key ? never : Key]: unknown };
type GraphqlTypeName = DeclaredKeys<ResolversTypes> & DeclaredKeys<Resolvers>;
type FieldResolvers<TypeName extends GraphqlTypeName> = NonNullable<Resolvers[TypeName]>;
type ResolverFunction<FieldResolver> = Extract<NonNullable<FieldResolver>, (...args: any[]) => any>;

/**
 * The functions of an edit mutations object, such as RetentionRuleEditMutations: graphql's default
 * resolver calls the function it finds on the parent object, with the arguments of the field. Each
 * function takes the arguments of its field and returns its value, as the generated resolvers describe them.
 */
export type EditMutationFunctions<TypeName extends GraphqlTypeName> = {
  [Field in DeclaredKeys<FieldResolvers<TypeName>>]?: (
    args: Parameters<ResolverFunction<FieldResolvers<TypeName>[Field]>>[1],
  ) => ReturnType<ResolverFunction<FieldResolvers<TypeName>[Field]>>;
};

/**
 * Types an edit mutations object as the graphql type it resolves to. The generated type describes the
 * values of its fields, not the functions graphql calls to get them: this cast is where the two meet,
 * and EditMutationFunctions checks every function against the schema.
 */
export const editMutations = <TypeName extends GraphqlTypeName>(functions: EditMutationFunctions<TypeName>) => {
  return functions as unknown as ResolversTypes[TypeName];
};
