import useAuth from './useAuth';
import { BYPASS, SETTINGS, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from './capabilities';

// Re-exported so existing `from 'useGranted'` imports keep working.
export * from './capabilities';

export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';

export const hasCapabilitiesInDraft = (capabilities: string[]) => {
  const { me } = useAuth();
  const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);
  return capabilities.some((capability) => (
    userCapabilitiesInDraft.includes(capability)
  ));
};

export const isOnlyOrganizationAdmin = () => {
  const { me: user } = useAuth();
  const userCapabilities = user.capabilities.map((n) => n.name);
  return userCapabilities.includes(VIRTUAL_ORGANIZATION_ADMIN) && !userCapabilities.includes(BYPASS) && !userCapabilities.includes(SETTINGS_SETACCESSES);
};

export const getCapabilitiesName = (capabilities: readonly { name: string }[]) => {
  return (capabilities ?? []).map((capability) => capability?.name);
};

export const isBypassUser = (me: { id: string; capabilities: readonly { name: string }[] }) => {
  const userCapabilities = getCapabilitiesName(me.capabilities);
  return userCapabilities.includes(BYPASS);
};

const checkCapabilities = (capabilities: string[], userCapabilities: string[], matchAll: boolean): boolean => {
  if (capabilities.length === 0) return false;
  const capabilityMatches = (requestedCapability: string) =>
    userCapabilities.some((u) => requestedCapability !== BYPASS && u.includes(requestedCapability));

  return matchAll ? capabilities.every(capabilityMatches) : capabilities.some(capabilityMatches);
};

type GrantedOptions = {
  capabilitiesInDraft?: string[];
};

// Pure version of `useGranted`, usable to check a list of items (hooks can't be called in a loop).
export const isGrantedTo = (
  me: ReturnType<typeof useAuth>['me'],
  capabilities: string[],
  matchAll = false,
  options: GrantedOptions = {},
): boolean => {
  const { capabilitiesInDraft } = options;

  // Prevent use of the old SETTINGS capability for future uses
  if (capabilities.includes(SETTINGS)) {
    throw new Error('The SETTINGS capability should not be used');
  }

  const userBaseCapabilities = getCapabilitiesName(me.capabilities);
  const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);

  if (isBypassUser(me)) {
    return true;
  }

  // Check base capabilities
  const baseGranted = checkCapabilities(capabilities, userBaseCapabilities, matchAll);

  // Check capabilities in Draft if provided
  const draftGranted = capabilitiesInDraft?.length
    ? checkCapabilities(capabilitiesInDraft, userCapabilitiesInDraft, matchAll)
    : false;

  // Check base and draft capabilities in draft context
  const draftGrantedInDraftContext = me.draftContext
    ? checkCapabilities(capabilities, [...userBaseCapabilities, ...userCapabilitiesInDraft], matchAll)
    : false;

  // Access is granted if EITHER check passes
  return baseGranted || draftGranted || draftGrantedInDraftContext;
};

const useGranted = (
  capabilities: string[],
  matchAll = false,
  options: GrantedOptions = {},
): boolean => {
  const { me } = useAuth();
  return isGrantedTo(me, capabilities, matchAll, options);
};

export default useGranted;
