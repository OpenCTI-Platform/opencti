import type { GroupsMapping, MappingConfiguration, OrganizationsMapping, UserInfoMapping } from './authenticationProvider-types';
import * as R from 'ramda';
import { pushAll } from '../../utils/arrayUtil';

export const resolvePath = async <T>(obj: any, [name, ...rest]: string[]): Promise<T | undefined> => {
  const { [name]: value } = obj;
  const isFunction = typeof value === 'function';
  const functionHasArgs = isFunction && value.length > 0;
  if (functionHasArgs) {
    const [argValue, ...restArgs] = rest;
    const resolvedValue = await value(argValue);
    if (restArgs.length === 0) {
      return resolvedValue;
    }
    return resolvePath(resolvedValue, restArgs);
  }

  const resolvedValue = typeof value === 'function' ? await value() : value;
  if (rest.length === 0) {
    return resolvedValue;
  }

  if (resolvedValue) {
    return resolvePath(resolvedValue, rest);
  }
  return undefined;
};

export const resolveDotPath = async <T>(obj: any, path: string): Promise<T | undefined> => resolvePath(obj, path.split('.'));

export const resolveUserInfo = async (
  { email_expr, name_expr, firstname_expr, lastname_expr }: UserInfoMapping,
  resolveExpr: (expr: string) => string | undefined | Promise<string | undefined>,
) => {
  return {
    email: await resolveExpr(email_expr),
    name: await resolveExpr(name_expr),
    firstname: firstname_expr ? await resolveExpr(firstname_expr) : undefined,
    lastname: lastname_expr ? await resolveExpr(lastname_expr) : undefined,
  };
};

export const resolveGroups = async (conf: GroupsMapping, resolveExpr: (expr: string) => undefined | string | string[] | Promise<undefined | string | string[]>) => {
  const allGroups: string[] = [];
  for await (const expr of conf.groups_expr) {
    const resolved = await resolveExpr(expr);
    if (resolved) {
      const groups = (Array.isArray(resolved) ? resolved : [resolved])
        .map((g) => conf.group_splitter ? g.split(conf.group_splitter) : [g])
        .flat();
      pushAll(allGroups, groups);
    }
  }

  const mappedGroups = allGroups.map(
    (g) => conf.groups_mapping.find(
      ({ provider }) => provider === g)?.platform,
  ).filter((m): m is string => Boolean(m));

  return R.uniq([...conf.default_groups, ...mappedGroups]);
};

export const resolveOrganizations = async (conf: OrganizationsMapping, resolveExpr: (expr: string) => undefined | string | string[] | Promise<undefined | string | string[]>) => {
  const allOrganization: string[] = [];
  for await (const expr of conf.organizations_expr) {
    const resolved = await resolveExpr(expr);
    if (resolved) {
      const groups = (Array.isArray(resolved) ? resolved : [resolved])
        .map((g) => conf.organizations_splitter ? g.split(conf.organizations_splitter) : [g])
        .flat();
      pushAll(allOrganization, groups);
    }
  }

  const mappedOrga = allOrganization.map(
    (o) => conf.organizations_mapping.find(
      ({ provider }) => provider === o)?.platform,
  ).filter((m): m is string => Boolean(m));

  return R.uniq([...conf.default_organizations, ...mappedOrga]);
};

export const createMappers = (conf: MappingConfiguration) => ({
  resolveGroups: (resolveExpr: (expr: string) => undefined | string | string[] | Promise<undefined | string | string[]>) => {
    return resolveGroups(conf.groups_mapping, resolveExpr);
  },
  resolveOrganizations: (resolveExpr: (expr: string) => undefined | string | string[] | Promise<undefined | string | string[]>) => {
    return resolveOrganizations(conf.organizations_mapping, resolveExpr);
  },
  resolveUserInfo: (resolveExpr: (expr: string) => string | undefined | Promise<string | undefined>) => {
    return resolveUserInfo(conf.user_info_mapping, resolveExpr);
  },
});
