import { getDirective, MapperKind, mapSchema } from '@graphql-tools/utils';
import type { GraphQLFieldConfig, GraphQLSchema } from 'graphql';
import { defaultFieldResolver } from 'graphql';
import { AuthRequired, ForbiddenAccess, LtsRequiredActivation, OtpRequired, OtpRequiredActivation, UnsupportedError } from '../config/errors';
import { Capabilities } from '../generated/graphql';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import type { AuthContext, AuthUser } from '../types/user';
import { BYPASS, checkOTPValidationStatus, OTPValidationStatus, SETTINGS_SET_ACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../utils/access';
import { getDraftContext } from '../utils/draftContext';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';

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
  /** Array of required capabilities in draft - must be valid Capabilities enum values */
  forDraft?: CapabilityString[];
  /** If true, ALL capabilities in 'for' are required. If false/undefined, ANY capability is sufficient */
  and?: boolean;
}

/**
 * Type for the directive argument maps stored by type name
 */
type TypeDirectiveArgumentMaps = Record<string, AuthDirectiveArgs>;

const TYPE_QUERY = 'Query';
const TYPE_MUTATION = 'Mutation';

const PUBLIC_PROTECT_DIRECTIVE = 'public';
const OTP_PROTECT_DIRECTIVE = 'allowUnprotectedOTP';
const LTS_PROTECT_DIRECTIVE = 'allowUnlicensedLTS';

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

const checkCapabilities = (capabilities: string[], userCapabilities: string[], matchAll: boolean): boolean => {
  if (capabilities.length === 0) return false;
  const capabilityMatches = (requestedCapability: string) =>
    userCapabilities.some((u) => requestedCapability !== BYPASS && u.includes(requestedCapability));

  return matchAll ? capabilities.every(capabilityMatches) : capabilities.some(capabilityMatches);
};

export const authDirectiveBuilder = (directiveName: string): AuthDirectiveBuilder => {
  const typeDirectiveArgumentMaps: TypeDirectiveArgumentMaps = {};

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

        if (!authDirective && (typeName === TYPE_QUERY || typeName === TYPE_MUTATION)) {
          const publicDirective = getDirective(schema, fieldConfig, PUBLIC_PROTECT_DIRECTIVE)?.[0];
          if (!publicDirective) {
            throw UnsupportedError('Unsecure schema: missing auth or public directive', { field: _fieldName });
          }
        }

        if (authDirective) {
          const { for: requiredCapabilitiesBase, and: requiredAll, forDraft: requiredCapabilitiesInDraft } = authDirective;

          if (requiredCapabilitiesBase || requiredCapabilitiesInDraft) {
            const { resolve = defaultFieldResolver } = fieldConfig;

            fieldConfig.resolve = (source: any, args: any, context: AuthContext, info: any) => {
              // Get user from the session
              const { user, blocked_for_lts_validation } = context;
              // Check user OTP status
              const allowUnprotectedOTP = !!getDirective(schema, fieldConfig, OTP_PROTECT_DIRECTIVE)?.[0];
              const otpStatus = checkOTPValidationStatus(context, allowUnprotectedOTP);
              switch (otpStatus) {
                case OTPValidationStatus.AUTHENTICATION_REQUIRED:
                  throw AuthRequired();
                case OTPValidationStatus.VALIDATION_REQUIRED:
                  throw OtpRequired();
                case OTPValidationStatus.ACTIVATION_REQUIRED:
                  throw OtpRequiredActivation();
                default:
                  break;
              }
              const authenticatedUser = user as AuthUser;
              // LTS version must be validated
              const allowUnlicensedLTS = !!getDirective(schema, fieldConfig, LTS_PROTECT_DIRECTIVE)?.[0];
              if (blocked_for_lts_validation && !allowUnlicensedLTS) {
                throw LtsRequiredActivation();
              }

              if (requiredCapabilitiesBase.length === 0 && requiredCapabilitiesInDraft?.length === 0) {
                return resolve(source, args, context, info);
              }

              const userBaseCapabilities = authenticatedUser.capabilities.map((c) => c.name);
              const userCapabilitiesInDraft = authenticatedUser.capabilitiesInDraft?.map((c) => c.name) ?? [];

              // Accept everything if bypass capability or the system user (protection).
              const shouldBypass = userBaseCapabilities.includes(BYPASS) || authenticatedUser.id === OPENCTI_ADMIN_UUID;
              if (shouldBypass) {
                return resolve(source, args, context, info);
              }

              // Check base capabilities
              const baseGranted = checkCapabilities(requiredCapabilitiesBase, userBaseCapabilities, !!requiredAll);

              // Check capabilities in Draft if provided
              const draftGranted = requiredCapabilitiesInDraft?.length
                ? checkCapabilities(requiredCapabilitiesInDraft, userCapabilitiesInDraft, !!requiredAll)
                : false;

              // Check base and draft capabilities in draft context
              const isInDraftContext = !!getDraftContext(context, user);
              const draftGrantedInDraftContext = isInDraftContext
                ? checkCapabilities(requiredCapabilitiesBase, [...userBaseCapabilities, ...userCapabilitiesInDraft], !!requiredAll)
                : false;

              // Access is granted if EITHER check passes
              const isGrantedAccess = baseGranted || draftGranted || draftGrantedInDraftContext;

              if (typeName === ENTITY_TYPE_IDENTITY_ORGANIZATION
                && requiredCapabilitiesBase.includes(VIRTUAL_ORGANIZATION_ADMIN)
                && !userBaseCapabilities.includes(SETTINGS_SET_ACCESSES)) {
                if (authenticatedUser.administrated_organizations.some(({ id }) => id === source.id)) {
                  return resolve(source, args, context, info);
                }
                return null;
              }

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
