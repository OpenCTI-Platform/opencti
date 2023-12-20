/* eslint-disable no-underscore-dangle,no-param-reassign */
import { getDirective, MapperKind, mapSchema } from '@graphql-tools/utils';
import { filter, includes, map } from 'ramda';
// eslint-disable-next-line import/extensions
import { defaultFieldResolver } from 'graphql/index.js';
import { AuthRequired, ForbiddenAccess, OtpRequired, OtpRequiredActivation } from '../config/errors';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import { BYPASS, VIRTUAL_ORGANIZATION_ADMIN, SETTINGS_SET_ACCESSES } from '../utils/access';
import { logApp } from '../config/conf';

/**
 * Retrieves the user's capabilities for an optionally specified entity type.
 * @param {*} user The user
 * @param {string?} entityType The entity type to look for in the user's role's overrides.
 * @returns {Record<string | number | symbol, any>} The user's capabilities
 */
const getUserCapabilities = (user, entityType = null) => {
  let userCapabilities = map((capability) => capability.name, user?.capabilities);

  // Handle bypass
  if (userCapabilities.includes(BYPASS) || user?.id === OPENCTI_ADMIN_UUID) {
    return userCapabilities;
  }

  try {
    if (entityType) {
      // Find the overrides of the user's role
      const overrides = user?.roles?.flatMap((role) => role?.capabilities_overrides);

      // Filter the overrides to be of the specified entity type
      const filteredOverrides = overrides
        ?.filter((capability) => capability?.entity.replace(/-/g, '') === entityType);

      // Map the override capabilities to just their names
      userCapabilities = map(
        (capability) => capability.name,
        filteredOverrides?.[0]?.capabilities
      );
    }
  } catch (error) {
    logApp.error(
      '[AUTH] Error occurred retrieving entity override capabilities',
      { error }
    );
  }
  return userCapabilities;
};

// eslint-disable-next-line
export const authDirectiveBuilder = (directiveName) => {
  const typeDirectiveArgumentMaps = {};
  return {
    authDirectiveTransformer: (schema) => mapSchema(schema, {
      [MapperKind.TYPE]: (type) => {
        const directive = getDirective(schema, type, directiveName);
        const authDirective = directive?.[0];
        if (authDirective) {
          typeDirectiveArgumentMaps[type.name] = authDirective;
        }
        return undefined;
      },
      [MapperKind.OBJECT_FIELD]: (fieldConfig, _fieldName, typeName) => {
        const directive = getDirective(schema, fieldConfig, directiveName);
        const authDirective = directive?.[0] ?? typeDirectiveArgumentMaps[typeName];
        if (authDirective) {
          const { for: requiredCapabilities, and: requiredAll, type: entityType } = authDirective;
          if (requiredCapabilities) {
            const { resolve = defaultFieldResolver } = fieldConfig;
            fieldConfig.resolve = (source, args, context, info) => {
              // Get user from the session
              const { user } = context;
              if (!user) {
                throw AuthRequired();
              } // User must be authenticated.
              const isProtectedMethod = info.fieldName !== 'logout'
                && info.fieldName !== 'otpLogin' && info.fieldName !== 'otpActivation' && info.fieldName !== 'otpGeneration';
              if (isProtectedMethod) {
                if (user.otp_mandatory) {
                  if (!user.otp_activated) {
                    throw OtpRequiredActivation();
                  }
                  if (!user.otp_validated) {
                    throw OtpRequired();
                  }
                } else if (user.otp_activated && !user.otp_validated) {
                  throw OtpRequired();
                }
              }
              // Start checking capabilities
              if (requiredCapabilities.length === 0) {
                return resolve(source, args, context, info);
              }
              // Compute user capabilities
              const userCapabilities = getUserCapabilities(user, entityType);
              // Accept everything if bypass capability or the system user (protection).
              const shouldBypass = userCapabilities.includes(BYPASS) || user.id === OPENCTI_ADMIN_UUID;
              if (shouldBypass) {
                return resolve(source, args, context, info);
              }
              if (typeName === 'Organization' && requiredCapabilities.includes(VIRTUAL_ORGANIZATION_ADMIN) && !userCapabilities.includes(SETTINGS_SET_ACCESSES)) {
                if (user.administrated_organizations.some(({ id }) => id === source.id)) {
                  return resolve(source, args, context, info);
                }
                return null;
              }
              // Check the user capabilities
              let numberOfAvailableCapabilities = 0;
              for (let index = 0; index < requiredCapabilities.length; index += 1) {
                const checkCapability = requiredCapabilities[index];
                const matchingCapabilities = filter((r) => includes(checkCapability, r), userCapabilities);
                if (matchingCapabilities.length > 0) {
                  numberOfAvailableCapabilities += 1;
                }
              }
              const isAccessForbidden = numberOfAvailableCapabilities === 0
                || (requiredAll && numberOfAvailableCapabilities !== requiredCapabilities.length);
              if (isAccessForbidden) {
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
