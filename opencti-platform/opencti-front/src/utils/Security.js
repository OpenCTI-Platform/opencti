import React from 'react';
import {
  flatten, map, pipe, uniq,
} from 'ramda';

export const UserContext = React.createContext({});
export const KNOWLEDGE = 'KNOWLEDGE';
export const KNOWLEDGE_KNIMPORT = 'KNOWLEDGE_KNIMPORT';
export const KNOWLEDGE_KNEXPORT = 'KNOWLEDGE_KNEXPORT';
export const KNOWLEDGE_KNCREATE = 'KNOWLEDGE_KNCREATE';
export const KNOWLEDGE_KNEDIT = 'KNOWLEDGE_KNEDIT';
export const SETTINGS = 'SETTINGS';

const granted = (me, roles, matchAll = false) => {
  const userCapabilities = pipe(
    map((c) => c.name),
    map((name) => name.split('_')),
    flatten,
    uniq,
  )(me.capabilities);
  if (!matchAll) return userCapabilities.some((r) => roles.includes(r));
  for (let index = 0; index < roles.length; index += 1) {
    const checkRole = roles[index];
    if (!userCapabilities.includes(checkRole)) return false;
  }
  return true;
};

const Security = ({
  roles, matchAll, children, placeholder = <span/>,
}) => (<UserContext.Consumer>{ (me) => {
  if (granted(me, roles, matchAll)) return children;
  return placeholder;
}}</UserContext.Consumer>);

export default Security;
