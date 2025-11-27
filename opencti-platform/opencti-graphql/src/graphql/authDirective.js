/* eslint-disable no-underscore-dangle,no-param-reassign */
import { getDirective, MapperKind, mapSchema } from '@graphql-tools/utils';
import { filter, includes, map } from 'ramda';
// eslint-disable-next-line import/extensions
import { defaultFieldResolver } from 'graphql/index.js';
import { AuthRequired, ForbiddenAccess, LtsRequiredActivation, OtpRequired, OtpRequiredActivation, UnsupportedError } from '../config/errors';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import { BYPASS, SETTINGS_SET_ACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../utils/access';

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
            fieldConfig.resolve = (source, args, context, info) => {
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
              const userCapabilities = map((c) => c.name, user.capabilities);
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
                const matchingCapabilities = filter((r) => checkCapability !== BYPASS && includes(checkCapability, r), userCapabilities);
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
