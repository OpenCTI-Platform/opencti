import { getDirective, MapperKind, mapSchema } from '@graphql-tools/utils';
import { defaultFieldResolver } from 'graphql';
import type { GraphQLFieldConfig, GraphQLSchema } from 'graphql';
import { ForbiddenAccess } from '../config/errors';
import type { AuthContext } from '../types/user';
import { isFeatureEnabled } from '../config/conf';

/**
 * Arguments passed to the feature-flagging directive in GraphQL schema
 * @example @ff(flags: ["SOME_FLAG", "SOME_OTHER_FLAG"], softFail: true)
 */
interface FeatureFlagDirectiveArgs {
  /**
   * Array of feature flags that allow access to the endpoint.
   * If at least one flag is set for current user then access
   * is granted. (i.e. an `or` operator is used between each one of them)
   */
  flags: string[];
  /**
   * If true indicates that a lack of enabled flag won't result
   * in an error but in returning the value `null`.
   * Can be useful for instance when querying very early in the app lifecycle
   * before feature flags being available in the client.
   * Defaults to `false`.
   */
  softFail?: boolean;
}

const FF_DIRECTIVE = 'ff';

export const makeFeatureFlagDirectiveTransformer = (): (schema: GraphQLSchema) => GraphQLSchema => {
  return (schema: GraphQLSchema) => mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig: GraphQLFieldConfig<any, any>, _fieldName: string) => {
      const directive = getDirective(schema, fieldConfig, FF_DIRECTIVE);
      const ffDirective = directive?.[0] as FeatureFlagDirectiveArgs | undefined;

      if (!ffDirective) {
        return fieldConfig;
      }

      const { flags, softFail } = ffDirective;
      if (!flags) {
        return fieldConfig;
      }

      const { resolve = defaultFieldResolver } = fieldConfig;
      fieldConfig.resolve = (source: any, args: any, context: AuthContext, info: any) => {
        if (!flags.some((flag) => isFeatureEnabled(flag))) {
          if (softFail) {
            return null;
          } else {
            throw ForbiddenAccess('Feature is disabled', { flags });
          }
        }
        return resolve(source, args, context, info);
      };
      return fieldConfig;
    },
  });
};
