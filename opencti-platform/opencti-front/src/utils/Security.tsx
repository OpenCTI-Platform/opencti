import React, { FunctionComponent, ReactElement, useContext } from 'react';
import { filter, includes } from 'ramda';
import { RootPrivateQuery$data } from '../private/__generated__/RootPrivateQuery.graphql';
import { ModuleHelper } from './platformModulesHelper';

export interface UserContextType {
  me: RootPrivateQuery$data['me'] | undefined;
  settings: RootPrivateQuery$data['settings'] | undefined;
  helper: ModuleHelper | undefined;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  helper: undefined,
};
export const UserContext = React.createContext<UserContextType>(defaultContext);

export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
export const BYPASS = 'BYPASS';
export const KNOWLEDGE = 'KNOWLEDGE';
export const KNOWLEDGE_KNUPDATE = 'KNOWLEDGE_KNUPDATE';
export const KNOWLEDGE_KNPARTICIPATE = 'KNOWLEDGE_KNPARTICIPATE';
export const KNOWLEDGE_KNUPDATE_KNDELETE = 'KNOWLEDGE_KNUPDATE_KNDELETE';
export const KNOWLEDGE_KNUPDATE_KNORGARESTRICT = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
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
export const CAPABILITY_INFORMATION = {
  [KNOWLEDGE_KNUPDATE_KNORGARESTRICT]: 'Granted only if user is a member of platform organization',
};

interface SecurityProps {
  children: ReactElement;
  needs: Array<string>;
  matchAll?: boolean;
  placeholder?: ReactElement;
}

interface DataSecurityProps extends SecurityProps {
  data: { createdBy: { id: string } };
}

export const granted = (
  me: RootPrivateQuery$data['me'] | undefined,
  capabilities: Array<string>,
  matchAll = false,
) => {
  const userCapabilities = (me?.capabilities ?? []).map((c) => c.name);
  if (userCapabilities.includes(BYPASS)) {
    return true;
  }
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

const Security: FunctionComponent<SecurityProps> = ({
  needs,
  matchAll,
  children,
  placeholder = <span />,
}) => {
  const { me } = useContext<UserContextType>(UserContext);
  if (me && granted(me, needs, matchAll)) {
    return children;
  }
  return placeholder;
};

export const CollaborativeSecurity: FunctionComponent<DataSecurityProps> = ({
  data,
  needs,
  matchAll,
  children,
  placeholder = <span />,
}) => {
  const { me } = useContext<UserContextType>(UserContext);
  const haveCapability = granted(me, needs, matchAll);
  if (haveCapability) {
    return children;
  }
  const canParticipate = granted(me, [KNOWLEDGE_KNPARTICIPATE], false);
  const isCreator = data.createdBy?.id ? data.createdBy?.id === me?.individual_id : false;
  if (canParticipate && isCreator) {
    return children;
  }
  return placeholder;
};

export default Security;
