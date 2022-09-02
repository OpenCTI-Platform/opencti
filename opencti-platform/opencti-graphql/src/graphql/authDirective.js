/* eslint-disable no-underscore-dangle,no-param-reassign */
import { mapSchema, MapperKind, getDirective } from '@graphql-tools/utils';
import { includes, map, filter } from 'ramda';
import { defaultFieldResolver, responsePathAsArray } from 'graphql';
import { AuthRequired, ForbiddenAccess, OtpRequired } from '../config/errors';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import { logAudit } from '../config/conf';
import { ACCESS_CONTROL } from '../config/audit';
import { BYPASS } from '../utils/access';

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
          const { for: requiredCapabilities, and: requiredAll } = authDirective;
          if (requiredCapabilities) {
            const { resolve = defaultFieldResolver } = fieldConfig;
            fieldConfig.resolve = (source, args, context, info) => {
              // Get user from the session
              const { user } = context;
              if (!user) {
                throw AuthRequired();
              } // User must be authenticated.
              const isOTP = user.otp_activated && user.otp_validated !== true;
              if (info.fieldName !== 'logout' && info.fieldName !== 'otpLogin' && isOTP) {
                throw OtpRequired();
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
                const executionPath = responsePathAsArray(info.path);
                logAudit.error(user, ACCESS_CONTROL, { path: executionPath });
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
