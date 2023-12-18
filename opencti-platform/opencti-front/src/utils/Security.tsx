import React, { FunctionComponent, ReactElement } from 'react';
import { filter, includes } from 'ramda';
import { RootPrivateQuery$data } from '../private/__generated__/RootPrivateQuery.graphql';
import useAuth from './hooks/useAuth';
import useGranted, { BYPASS, KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from './hooks/useGranted';
import useKnowledgeGranted from './hooks/useKnowledgeGranted';

export const CAPABILITY_INFORMATION = {
  [KNOWLEDGE_KNUPDATE_KNORGARESTRICT]:
    'Granted only if user is a member of platform organization',
};

interface SecurityProps {
  children: ReactElement;
  needs: string[];
  hasAccess?: boolean;
  matchAll?: boolean;
  placeholder?: ReactElement;
}

interface KnowledgeSecurityProps extends SecurityProps {
  entity: string;
}

interface DataSecurityProps extends SecurityProps {
  data: { createdBy: { id: string } | null | undefined };
}

// DEPECRATED
export const granted = (
  me: RootPrivateQuery$data['me'],
  capabilities: string[],
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
  matchAll = false,
  hasAccess = true,
  children,
  placeholder = <span />,
}) => {
  const isGranted = useGranted(needs, matchAll);
  return isGranted && hasAccess ? children : placeholder;
};

export const KnowledgeSecurity: FunctionComponent<KnowledgeSecurityProps> = ({
  needs,
  entity,
  matchAll = false,
  hasAccess = true,
  children,
  placeholder = <span />,
}) => {
  const isGranted = useKnowledgeGranted(needs, entity, matchAll);
  return isGranted && hasAccess ? children : placeholder;
};

export const CollaborativeSecurity: FunctionComponent<DataSecurityProps> = ({
  data,
  needs,
  matchAll,
  children,
  placeholder = <span />,
}) => {
  const { me } = useAuth();
  const haveCapability = useGranted(needs, matchAll);
  const canParticipate = useGranted([KNOWLEDGE_KNPARTICIPATE]);
  if (haveCapability) {
    return children;
  }
  const isCreator = data.createdBy?.id
    ? data.createdBy?.id === me.individual_id
    : false;
  if (canParticipate && isCreator) {
    return children;
  }
  return placeholder;
};

export default Security;
