import useAuth from './useAuth';
import useHelper from './useHelper';

const PROTECT_SENSITIVE_CHANGES_FF = 'PROTECT_SENSITIVE_CHANGES';

const ADMINISTRATORS_GROUP_ID = 'group--1d9d9a2a-d7e1-5a22-8e90-572d597750ac';
const CONNECTORS_GROUP_ID = 'group--599fc7ab-02f4-50c1-94f9-4b68da122010';
const DEFAULT_GROUP_ID = 'group--a7991a4f-6192-59a4-87d3-d006d2c41cc8';
const PROTECTED_GROUPS_IDS = [ADMINISTRATORS_GROUP_ID, CONNECTORS_GROUP_ID, DEFAULT_GROUP_ID];

const ADMINISTRATOR_ROLE_ID = 'role--22abb1ff-6ea9-5833-8bf1-aea5c4c971ce';
const CONNECTOR_ROLE_ID = 'role--b375ed46-a11c-56d5-a2d4-0c654f61eeee';
const DEFAULT_ROLE_ID = 'role--a7991a4f-6192-59a4-87d3-d006d2c41cc8';
const PROTECTED_ROLES_IDS = [ADMINISTRATOR_ROLE_ID, CONNECTOR_ROLE_ID, DEFAULT_ROLE_ID];

const STATMENT_1 = 'marking-definition--934134c7-9679-56d5-a8c9-4fb76064a41a'; // copyright 2015-2024, the mitre ...
const STATMENT_2 = 'marking-definition--e8afcdc4-be08-5e57-a3b6-c24d2396d3de'; // Copyright 2017, The MITRE Corporation
const PAP_AMBER = 'marking-definition--a6f20d4d-0360-59b6-ba22-3b48707828b1';
const PAP_CLEAR = 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34';
const PAP_GREEN = 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1';
const PAP_RED = 'marking-definition--4e4e3b84-de45-53df-9d9b-b21207699fd8';
const TLP_AMBER = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82';
const TLP_AMBER_STRICT = 'marking-definition--826578e1-40ad-459f-bc73-ede076f81f37';
const TLP_CLEAR = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';
const TLP_GREEN = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da';
const TLP_RED = 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed';
const TLP_TEST = 'marking-definition--907bb632-e3c2-52fa-b484-cf166a7d377c';
const PROTECTED_MARKINGS_IDS = [STATMENT_1, STATMENT_2, PAP_AMBER, PAP_CLEAR, PAP_GREEN, PAP_RED, TLP_AMBER, TLP_AMBER_STRICT, TLP_CLEAR, TLP_GREEN, TLP_RED, TLP_TEST];

const PROTECTED_IDS = [...PROTECTED_GROUPS_IDS, ...PROTECTED_ROLES_IDS, ...PROTECTED_MARKINGS_IDS];

const useSensitiveModifications = (id?: string) => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const isSensitiveModificationEnabled = isFeatureEnable(PROTECT_SENSITIVE_CHANGES_FF);

  let isAllowed = me.can_manage_sensitive_config != null ? me.can_manage_sensitive_config : true;

  if (id) {
    isAllowed = (me.can_manage_sensitive_config || !PROTECTED_IDS.includes(id));
  }
  if (!isSensitiveModificationEnabled) {
    isAllowed = true;
  }

  return {
    isSensitiveModificationEnabled,
    isAllowed,
    isSensitive: isSensitiveModificationEnabled && (!id || PROTECTED_IDS.includes(id)),
  };
};

export default useSensitiveModifications;
