import { getDirective, MapperKind, mapSchema } from '@graphql-tools/utils';
// eslint-disable-next-line import/extensions
import { defaultFieldResolver } from 'graphql/index.js';
import type { GraphQLFieldConfig, GraphQLSchema } from 'graphql';
import { AuthRequired, ForbiddenAccess, LtsRequiredActivation, OtpRequired, OtpRequiredActivation, UnsupportedError } from '../config/errors';
import { Capabilities } from '../generated/graphql';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import type { AuthContext } from '../types/user';
import { BYPASS, SETTINGS_SET_ACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../utils/access';
import { getDraftContext } from '../utils/draftContext';
import { isFeatureEnabled } from '../config/conf';

/**
 * Type representing a capability string value from the Capabilities enum
 */
type CapabilityString = `${Capabilities}`;

/**
 * Arguments passed to the auth directive in GraphQL schema
 * @example @auth(for: ["KNOWLEDGE_KNUPDATE"], and: true)
 */
interface AuthDirectiveArgs {
  /** Array of required capabilities - must be valid Capabilities enum values */
  for: CapabilityString[];
  /** If true, ALL capabilities in 'for' are required. If false/undefined, ANY capability is sufficient */
  and?: boolean;
}

/**
 * Type for the directive argument maps stored by type name
 */
type TypeDirectiveArgumentMaps = Record<string, AuthDirectiveArgs>;

/**
 * Return type of authDirectiveBuilder function
 */
interface AuthDirectiveBuilder {
  /**
   * Transforms a GraphQL schema by applying auth directive logic
   * @param schema - The GraphQL schema to transform
   * @returns The transformed schema with auth checks
   */
  authDirectiveTransformer: (schema: GraphQLSchema) => GraphQLSchema;
}

export const authDirectiveBuilder = (directiveName: string): AuthDirectiveBuilder => {
  const typeDirectiveArgumentMaps: TypeDirectiveArgumentMaps = {};
  const isCapabilitiesInDraftEnabled = isFeatureEnabled('CAPABILITIES_IN_DRAFT');
  return {
    authDirectiveTransformer: (schema: GraphQLSchema) => mapSchema(schema, {
      [MapperKind.TYPE]: (type) => {
        const directive = getDirective(schema, type, directiveName);
        const authDirective = directive?.[0] as AuthDirectiveArgs | undefined;
        if (authDirective) {
          typeDirectiveArgumentMaps[type.name] = authDirective;
        }
        return undefined;
      },
      [MapperKind.OBJECT_FIELD]: (fieldConfig: GraphQLFieldConfig<any, any>, _fieldName: string, typeName: string) => {
        const directive = getDirective(schema, fieldConfig, directiveName);
        const authDirective = (directive?.[0] as AuthDirectiveArgs | undefined) ?? typeDirectiveArgumentMaps[typeName];
        if (!authDirective && (typeName === 'Query' || typeName === 'Mutation')) {
          const publicDirective = getDirective(schema, fieldConfig, 'public')?.[0];
          if (!publicDirective) {
            throw UnsupportedError('Unsecure schema: missing auth or public directive', { field: _fieldName });
          }
        }
        if (authDirective) {
          const { for: requiredCapabilities, and: requiredAll } = authDirective;
          if (requiredCapabilities) {
            const { resolve = defaultFieldResolver } = fieldConfig;
            fieldConfig.resolve = (source: any, args: any, context: AuthContext, info: any) => {
              // Get user from the session
              const { user, otp_mandatory, user_otp_validated, blocked_for_lts_validation } = context;
              // User must be authenticated.
              if (!user) {
                throw AuthRequired();
              }
              const isProtectedMethod = info.fieldName !== 'logout'
                && info.fieldName !== 'otpLogin' && info.fieldName !== 'otpActivation' && info.fieldName !== 'otpGeneration';
              if (isProtectedMethod) {
                // If the platform enforce OTP
                if (otp_mandatory) {
                  // If user have not validated is OTP in session
                  // by default user_otp_validated is true for direct api usage
                  if (!user_otp_validated) {
                    // If OTP is not setup, return a specific error
                    if (!user.otp_activated) {
                      throw OtpRequiredActivation();
                    }
                    // If already setup but not validated, return the validation screen
                    throw OtpRequired();
                  }
                } else if (user.otp_activated && !user_otp_validated) {
                  // If user self activate OTP, session must be validated
                  throw OtpRequired();
                }
              }
              // LTS version must be validated
              const allowUnlicensedLTS = !!getDirective(schema, fieldConfig, 'allowUnlicensedLTS')?.[0];
              if (blocked_for_lts_validation && !allowUnlicensedLTS) {
                throw LtsRequiredActivation();
              }
              // Start checking capabilities
              if (requiredCapabilities.length === 0) {
                return resolve(source, args, context, info);
              }
              // Compute user capabilities
              const userBaseCapabilities = user.capabilities.map((c) => c.name);
              // Accept everything if bypass capability or the system user (protection).
              const shouldBypass = userBaseCapabilities.includes(BYPASS) || user.id === OPENCTI_ADMIN_UUID;
              if (shouldBypass) {
                return resolve(source, args, context, info);
              }
              
              let userCapabilities: string[] = [];

              const isInDraftContext = !!getDraftContext(context, user);
              // If the user is in draft mode, add capabilities in draft to the base capabilities
              if (isCapabilitiesInDraftEnabled && isInDraftContext) {
                const userCapabilitiesInDraft = user.capabilitiesInDraft?.map((c) => c.name) ?? [];
                userCapabilities = Array.from(new Set([...userBaseCapabilities, ...userCapabilitiesInDraft]));
              } else {
                userCapabilities = userBaseCapabilities;
              }
              
              if (typeName === 'Organization' && requiredCapabilities.includes(VIRTUAL_ORGANIZATION_ADMIN) && !userCapabilities.includes(SETTINGS_SET_ACCESSES)) {
                if (user.administrated_organizations.some(({ id }) => id === source.id)) {
                  return resolve(source, args, context, info);
                }
                return null;
              }

              const capabilityMatches = (requestedCapability: string) =>
                // Check if any of the user capabilities includes the requested capability as a substring
                userCapabilities.some((u) => requestedCapability !== BYPASS && u.includes(requestedCapability));

              const isGrantedAccess = requiredAll
                ? requiredCapabilities.every(capabilityMatches)
                : requiredCapabilities.some(capabilityMatches);

              if (!isGrantedAccess) {
                throw ForbiddenAccess();
              }
              return resolve(source, args, context, info);
            };
            return fieldConfig;
          }
        }
        return fieldConfig;
      },
    }),
  };
};
