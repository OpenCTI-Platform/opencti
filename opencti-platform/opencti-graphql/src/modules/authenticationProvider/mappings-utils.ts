import type { GroupsMapping, MappingConfiguration, OrganizationsMapping, UserInfoMapping } from './authenticationProvider-types';
import * as R from 'ramda';
import { pushAll } from '../../utils/arrayUtil';
import type { ProviderAuthInfo } from './providers';

/**
 * Looks up a property on a record: first case-sensitive, then case-insensitive fallback.
 */
const resolveRecordValue = (record: { [key: string]: unknown }, name: string): unknown => {
  const exact = record[name];
  if (exact !== undefined && exact !== null) {
    return exact;
  }
  const lowerName = name.toLowerCase();
  const key = Object.keys(record).find((k) => k.toLowerCase() === lowerName);
  return key !== undefined ? record[key] : undefined;
};

export const resolvePath = (path: string[]) => async (obj: unknown): Promise<any | undefined> => {
  if (obj === undefined || obj === null) {
    return undefined;
  }

  if (Array.isArray(obj)) {
    const results: any[] = [];
    for await (const v of obj) {
      const resolved = await resolvePath(path)(v);
      if (resolved !== undefined && resolved !== null) {
        results.push(resolved);
      }
    }
    return results;
  }

  const [name, ...rest] = path;
  const value = resolveRecordValue(obj as { [key: string]: unknown }, name);
  if (value === undefined || value === null) {
    return undefined;
  }

  const isFunction = typeof value === 'function';
  const functionHasArgs = isFunction && value.length > 0;
  const [remaining, argValue] = functionHasArgs ? [rest.slice(1), rest[0]] : [rest];
  const resolvedValue = isFunction ? await value(argValue) : value;
  if (remaining.length === 0) {
    return resolvedValue ?? undefined; // normalize null to undefined for consistency
  }

  return resolvePath(remaining)(resolvedValue);
};

/**
 * Parses a dot-separated path string into segments.
 * Path components that contain dots (e.g. SAML HTTP claim URIs) can be quoted with double quotes.
 * Inside quoted segments, use "" to represent a literal double quote.
 * Example: user_info."http://example.com/claims/email" → ['user_info', 'http://example.com/claims/email']
 */
export const parseDotPath = (path: string): string[] => {
  // Unquoted [^."]+ or quoted "((?:[^"]|"")*)", then . or end. "" inside quotes = literal ".
  const re = /(?:([^."]+)|"((?:[^"]|"")*)")(?:\.|$)/g;
  const segments: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(path)) !== null) {
    const segment = m[1] !== undefined ? m[1] : m[2].replace(/""/g, '"');
    segments.push(segment);
  }
  return segments;
};

export const resolveDotPath = (path: string) => resolvePath(parseDotPath(path));

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
    const s = await emailExpr(obj);
    return {
      email: firstElement(s)?.trim(),
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
          .map((s) => s?.trim())
          .filter(Boolean),
      );
    }
  }

  const mapped = allValues.map(
    (g) => {
      // First try case-sensitive match
      const exactMatch = mapping.find(({ provider }) => provider === g);
      if (exactMatch) return exactMatch.platform;
      // Fallback to case-insensitive match
      const lowerG = g.toLowerCase();
      return mapping.find(({ provider }) => provider.toLowerCase() === lowerG)?.platform;
    },
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
