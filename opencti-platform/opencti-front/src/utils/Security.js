import React from 'react';
import {
  flatten, map, pipe, uniq,
} from 'ramda';

export const UserContext = React.createContext({});

export const BYPASS = 'BYPASS';
export const CONNECTORAPI = 'CONNECTORAPI';
export const KNOWLEDGE = 'KNOWLEDGE';
export const KNOWLEDGE_KNUPDATE = 'KNOWLEDGE_KNUPDATE';
export const KNOWLEDGE_KNDELETE = 'KNOWLEDGE_KNDELETE';
export const KNOWLEDGE_KNUPLOAD = 'KNOWLEDGE_KNUPLOAD';
export const KNOWLEDGE_KNASKIMPORT = 'KNOWLEDGE_KNASKIMPORT';
export const KNOWLEDGE_KNGETEXPORT = 'KNOWLEDGE_KNGETEXPORT';
export const KNOWLEDGE_KNGETEXPORT_KNASKEXPORT = 'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT';
export const KNOWLEDGE_KNENRICHMENT = 'KNOWLEDGE_KNENRICHMENT';
export const EXPLORE = 'EXPLORE';
export const EXPLORE_EXUPDATE = 'EXPLORE_EXUPDATE';
export const EXPLORE_EXDELETE = 'EXPLORE_EXDELETE';
export const MODULES = 'MODULES';
export const MODULES_MODMANAGE = 'MODULES_MODMANAGE';
export const SETTINGS = 'SETTINGS';
export const SETTINGS_SETINFERENCES = 'SETTINGS_SETINFERENCES';
export const SETTINGS_SETACCESSES = 'SETTINGS_SETACCESSES';
export const SETTINGS_SETMARKINGS = 'SETTINGS_SETMARKINGS';

const granted = (me, roles, matchAll = false) => {
  const userCapabilities = pipe(
    map((c) => c.name),
    map((name) => name.split('_')),
    flatten,
    uniq,
  )(me.capabilities);
  if (userCapabilities.includes(BYPASS)) return true;
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
