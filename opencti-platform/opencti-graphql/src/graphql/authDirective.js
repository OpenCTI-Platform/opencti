/* eslint-disable no-underscore-dangle,no-param-reassign */
import { SchemaDirectiveVisitor } from 'graphql-tools';
import { includes, map, filter } from 'ramda';
import { defaultFieldResolver } from 'graphql';
import { AuthRequired, ForbiddenAccess } from '../config/errors';
import { BYPASS, OPENCTI_ADMIN_UUID } from '../domain/user';

export const AUTH_DIRECTIVE = 'auth';

// Auth code get from https://www.apollographql.com/docs/graphql-tools/schema-directives.html
// Use object mutation and not conform with eslint but it works pretty well.
class AuthDirective extends SchemaDirectiveVisitor {
  visitObject(type) {
    this.ensureFieldsWrapped(type);
    // noinspection JSUndefinedPropertyAssignment
    type._requiredCapabilities = this.args.for;
    type._requiredAll = this.args.and;
  }

  visitFieldDefinition(field, details) {
    this.ensureFieldsWrapped(details.objectType);
    field._requiredCapabilities = this.args.for;
    field._requiredAll = this.args.and;
  }

  authenticationControl(func, args, objectType, field) {
    // Get the required Role from the field first, falling back
    // to the objectType if no Role is required by the field:
    const requiredCapabilities = field._requiredCapabilities || objectType._requiredCapabilities || [];
    const requiredAll = field._requiredAll || objectType._requiredAll || false;
    // If a role is required
    const context = args[2];
    const { user } = context;
    if (!user) throw new AuthRequired(); // User must be authenticated.
    // Start checking capabilities
    if (requiredCapabilities.length === 0) return func.apply(this, args);
    // Compute user capabilities
    const userCapabilities = map((c) => c.name, user.capabilities);
    // Accept everything if bypass capability or the system user (protection).
    const shouldBypass = userCapabilities.includes(BYPASS) || user.id === OPENCTI_ADMIN_UUID;
    if (shouldBypass) return func.apply(this, args);
    // Check the user capabilities
    const availableCapabilities = [];
    for (let index = 0; index < requiredCapabilities.length; index += 1) {
      const checkCapability = requiredCapabilities[index];
      const matchingCapabilities = filter((r) => includes(checkCapability, r), userCapabilities);
      if (matchingCapabilities.length > 0) availableCapabilities.push(checkCapability);
    }
    if (availableCapabilities.length === 0) throw new ForbiddenAccess();
    if (requiredAll && availableCapabilities.length !== requiredCapabilities.length) throw new ForbiddenAccess();
    return func.apply(this, args);
  }

  ensureFieldsWrapped(objectType) {
    const $this = this;
    if (objectType._authFieldsWrapped) return;
    objectType._authFieldsWrapped = true;
    const fields = objectType.getFields();
    Object.keys(fields).forEach((fieldName) => {
      const field = fields[fieldName];
      const { directives } = field.astNode;
      const directiveNames = map((d) => d.name.value, directives);
      const { resolve = defaultFieldResolver, subscribe } = field;
      field.resolve = (...args) =>
        includes(AUTH_DIRECTIVE, directiveNames)
          ? $this.authenticationControl(resolve, args, objectType, field)
          : resolve.apply($this, args);
      if (subscribe) {
        field.subscribe = (...args) => $this.authenticationControl(subscribe, args, objectType, field);
      }
    });
  }
}

export default AuthDirective;
