import type { GroupsMapping, MappingConfiguration, OrganizationsMapping, UserInfoMapping } from './authenticationProvider-types';
import * as R from 'ramda';
import { pushAll } from '../../utils/arrayUtil';
import type { ProviderAuthInfo } from './providers';

export const resolvePath = ([name, ...rest]: string[]) => async <T>(obj: unknown): Promise<T | undefined> => {
  const { [name]: value } = (obj ?? {}) as { [key: string]: unknown };
  if (value === undefined || obj === null) {
    return undefined;
  }

  const isFunction = typeof value === 'function';
  const functionHasArgs = isFunction && value.length > 0;
  const [argValue] = functionHasArgs ? rest.splice(0, 1) : [];
  const resolvedValue = isFunction ? await value(argValue) : value;
  if (rest.length === 0) {
    return resolvedValue;
  }

  return resolvePath(rest)(resolvedValue);
};

export const resolveDotPath = (path: string) => resolvePath(path.split('.'));

type ResolveExprFunction = (obj: unknown) => undefined | string | string[] | Promise<undefined | string | string[]>;
type CreateResolveExprFunction = (expr: string) => ResolveExprFunction;

const firstElement = (s: string | string[] | undefined) => Array.isArray(s) ? s.find((s) => Boolean(s)) : s;

export const createUserMapper = (
  { email_expr, name_expr, firstname_expr, lastname_expr }: UserInfoMapping,
  resolveExpr: CreateResolveExprFunction,
) => {
  const emailExpr = resolveExpr(email_expr);
  const nameExpr = resolveExpr(name_expr);
  const firstnameExpr = firstname_expr ? resolveExpr(firstname_expr) : () => undefined;
  const lastnameExpr = lastname_expr ? resolveExpr(lastname_expr) : () => undefined;
  return async (obj: unknown) => {
    return {
      email: firstElement(await emailExpr(obj))?.trim(),
      name: firstElement(await nameExpr(obj))?.trim(),
      firstname: firstElement(await firstnameExpr(obj))?.trim(),
      lastname: firstElement(await lastnameExpr(obj))?.trim(),
    };
  };
};

const extractSplitMapAndDeduplicate = async (
  obj: unknown,
  resolvers: ResolveExprFunction[],
  splitter: string | undefined,
  mapping: { provider: string; platform: string }[],
  defaultValues: string[],
) => {
  const allValues: string[] = [];
  for await (const resolver of resolvers) {
    const resolved = await resolver(obj);
    if (resolved) {
      pushAll(
        allValues,
        (Array.isArray(resolved) ? resolved : [resolved])
          .map((g) => splitter ? g.split(splitter) : [g])
          .flat()
          .map((s) => s.trim()),
      );
    }
  }

  const mapped = allValues.map(
    (g) => mapping.find(
      ({ provider }) => provider === g)?.platform,
  ).filter((m): m is string => Boolean(m));

  return R.uniq([...defaultValues, ...mapped]);
};

export const createGroupsMapper = (conf: GroupsMapping, resolveExpr: CreateResolveExprFunction) => {
  const groupExprs = conf.groups_expr.map((expr) => resolveExpr(expr));
  return (obj: unknown) => extractSplitMapAndDeduplicate(obj, groupExprs, conf.group_splitter, conf.groups_mapping, conf.default_groups);
};

export const createOrganizationsMapper = (conf: OrganizationsMapping, resolveExpr: CreateResolveExprFunction) => {
  const orgaExprs = conf.organizations_expr.map((expr) => resolveExpr(expr));
  return (obj: unknown) => extractSplitMapAndDeduplicate(obj, orgaExprs, conf.organizations_splitter, conf.organizations_mapping, conf.default_organizations);
};

export const createMapper = (
  conf: MappingConfiguration,
  resolveExpr: (expr: string) => (obj: unknown) => undefined | string | string[] | Promise<undefined | string | string[]> = resolveDotPath,
) => {
  const userMapper = createUserMapper(conf.user_info_mapping, resolveExpr);
  const groupsMapper = createGroupsMapper(conf.groups_mapping, resolveExpr);
  const organizationsMapper = createOrganizationsMapper(conf.organizations_mapping, resolveExpr);

  return async (userContext: unknown, groupContext = userContext, organizationContext = userContext): Promise<ProviderAuthInfo> => {
    const userMapping = await userMapper(userContext);
    const groups = await groupsMapper(groupContext);
    const organizations = await organizationsMapper(organizationContext);
    return {
      userMapping,
      groupsMapping: {
        groups,
        autoCreateGroup: conf.groups_mapping.auto_create_groups,
        preventDefaultGroups: conf.groups_mapping.prevent_default_groups,
      },
      organizationsMapping: {
        organizations,
        autoCreateOrganization: conf.organizations_mapping.auto_create_organizations,
      },
    };
  };
};
