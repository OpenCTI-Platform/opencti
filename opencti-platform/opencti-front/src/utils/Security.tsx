import React, { FunctionComponent, useContext } from 'react';
import { filter, includes, map } from 'ramda';

interface Capability {
  id: string;
  name: string;
}

export interface Me {
  theme: string;
  capabilities: Array<Capability>;
}

export interface UserContextType {
  me: Me | undefined;
}

export const UserContext = React.createContext<UserContextType>({ me: undefined });

export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
export const BYPASS = 'BYPASS';
export const KNOWLEDGE = 'KNOWLEDGE';
export const KNOWLEDGE_KNUPDATE = 'KNOWLEDGE_KNUPDATE';
export const KNOWLEDGE_KNUPDATE_KNDELETE = 'KNOWLEDGE_KNUPDATE_KNDELETE';
export const KNOWLEDGE_KNUPLOAD = 'KNOWLEDGE_KNUPLOAD';
export const KNOWLEDGE_KNASKIMPORT = 'KNOWLEDGE_KNASKIMPORT';
export const KNOWLEDGE_KNGETEXPORT = 'KNOWLEDGE_KNGETEXPORT';
export const KNOWLEDGE_KNGETEXPORT_KNASKEXPORT = 'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT';
export const KNOWLEDGE_KNENRICHMENT = 'KNOWLEDGE_KNENRICHMENT';
export const EXPLORE = 'EXPLORE';
export const EXPLORE_EXUPDATE = 'EXPLORE_EXUPDATE';
export const MODULES = 'MODULES';
export const MODULES_MODMANAGE = 'MODULES_MODMANAGE';
export const SETTINGS = 'SETTINGS';
export const TAXIIAPI_SETCOLLECTIONS = 'TAXIIAPI_SETCOLLECTIONS';
export const SETTINGS_SETACCESSES = 'SETTINGS_SETACCESSES';
export const SETTINGS_SETLABELS = 'SETTINGS_SETLABELS';

interface SecurityProps {
  children: React.ReactNode
  needs: Array<string>
  matchAll: boolean
  // eslint-disable-next-line
  placeholder: any
}

export const granted = (me: Me, capabilities: Array<string>, matchAll = false) => {
  const userCapabilities = map((c) => c.name, me.capabilities);
  if (userCapabilities.includes(BYPASS)) return true;
  let numberOfAvailableCapabilities = 0;
  for (let index = 0; index < capabilities.length; index += 1) {
    const checkCapability = capabilities[index];
    const matchingCapabilities = filter(
      (r) => includes(checkCapability, r),
      userCapabilities,
    );
    if (matchingCapabilities.length > 0) {
      numberOfAvailableCapabilities += 1;
    }
  }
  if (matchAll) {
    return numberOfAvailableCapabilities === capabilities.length;
  }
  return numberOfAvailableCapabilities > 0;
};

const Security: FunctionComponent<SecurityProps> = ({ needs, matchAll, children, placeholder = <span /> }) => {
  const userContext = useContext(UserContext);
  if (userContext.me && granted(userContext.me, needs, matchAll)) {
    return children;
  }
  return placeholder;
};

export default Security;
