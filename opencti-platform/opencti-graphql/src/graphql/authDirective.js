/* eslint-disable no-underscore-dangle,no-param-reassign */
import { MapperKind, mapSchema, SchemaDirectiveVisitor } from '@graphql-tools/utils';
import { filter, includes, map } from 'ramda';
import { defaultFieldResolver, responsePathAsArray } from 'graphql';
import { AuthRequired, ForbiddenAccess } from '../config/errors';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import { logAudit } from '../config/conf';
import { ACCESS_CONTROL } from '../config/audit';
import { BYPASS } from '../utils/access';

export const AUTH_DIRECTIVE = 'auth';

const authenticationControl = (func, args, type, field) => {
  // Get the required Role from the field first, falling back
  // to the objectType if no Role is required by the field:
  const requiredCapabilities = type._requiredCapabilities || field._requiredCapabilities || [];
  const requiredAll = type._requiredAll || field._requiredAll || false;
  // If a role is required
  const context = args[2];
  const { user } = context;

  if (!user) throw AuthRequired(); // User must be authenticated.
  // Start checking capabilities
  if (requiredCapabilities.length === 0) return func.apply(this, args);
  // Compute user capabilities
  const userCapabilities = map((c) => c.name, user.capabilities);
  // Accept everything if bypass capability or the system user (protection).
  const shouldBypass = userCapabilities.includes(BYPASS) || user.id === OPENCTI_ADMIN_UUID;
  if (shouldBypass) return func.apply(this, args);
  // Check the user capabilities
  let numberOfAvailableCapabilities = 0;
  for (let index = 0; index < requiredCapabilities.length; index += 1) {
    const checkCapability = requiredCapabilities[index];
    const matchingCapabilities = filter((r) => includes(checkCapability, r), userCapabilities);
    if (matchingCapabilities.length > 0) {
      numberOfAvailableCapabilities += 1;
    }
  }
  const isAccessForbidden =
    numberOfAvailableCapabilities === 0 ||
    (requiredAll && numberOfAvailableCapabilities !== requiredCapabilities.length);
  if (isAccessForbidden) {
    const [, , , info] = args;
    const executionPath = responsePathAsArray(info.path);
    logAudit.error(user, ACCESS_CONTROL, { path: executionPath });
    throw ForbiddenAccess();
  }
  return func.apply(this, args);
};

const visitConfig = (config) => {
  const directive = config.astNode.directives?.filter((d) => d.name.value === AUTH_DIRECTIVE)[0];
  if (directive) {
    const forArg = directive.arguments.filter((a) => a.name.value === 'for')?.[0];
    if (forArg) {
      config._requiredCapabilitites = forArg.value.values.map((v) => v.value);
    }
    const { resolve } = config;
    config.resolve = (...args) => authenticationControl(resolve, args, config);
  }
  return config;
};

export const authDirectiveV2 = () => {
  return {
    authDirectiveTransformer: (schema) =>
      mapSchema(schema, {
        [MapperKind.OBJECT_TYPE]: (objType) => {
          if (objType._visited) return objType;
          objType._visited = true;
          const fields = objType.getFields();
          Object.keys(fields).forEach((fieldName) => {
            const field = fields[fieldName];
            const { directives } = field.astNode;
            const directiveNames = map((d) => d.name.value, directives);
            const { resolve = defaultFieldResolver, subscribe } = field;
            field.resolve = (...args) =>
              includes(AUTH_DIRECTIVE, directiveNames)
                ? authenticationControl(resolve, args, objType, field)
                : resolve.apply(this, args);
            const authDir = directives.filter((d) => d.name.value === AUTH_DIRECTIVE)?.[0];
            if (authDir) {
              const forArg = authDir.arguments.filter((arg) => arg.name.value === 'for')?.[0];
              field._requiredCapabilities = forArg ? forArg.value.values.map((v) => v.value) : [];
            }
            if (subscribe) {
              field.subscribe = (...args) => authenticationControl(subscribe, args, objType, field);
            }
          });
          return objType;
        },
      }),
  };
};
