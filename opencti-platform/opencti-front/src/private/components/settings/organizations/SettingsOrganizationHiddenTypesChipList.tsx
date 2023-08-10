import React from 'react';
import { graphql, useFragment } from 'react-relay';
import HiddenTypesChipList from '../hidden_types/HiddenTypesChipList';
import { SettingsOrganization_organization$data } from './__generated__/SettingsOrganization_organization.graphql';
import {
  SettingsOrganizationHiddenTypesChipList_organization$key,
} from './__generated__/SettingsOrganizationHiddenTypesChipList_organization.graphql';

const settingsOrganizationHiddenTypesChipListFragment = graphql`
  fragment SettingsOrganizationHiddenTypesChipList_organization on Organization {
    default_hidden_types
  }
`;

const SettingsOrganizationHiddenTypesChipList = ({
  organizationData,
}: {
  organizationData: SettingsOrganization_organization$data
}) => {
  const organization = useFragment(settingsOrganizationHiddenTypesChipListFragment, organizationData as unknown as SettingsOrganizationHiddenTypesChipList_organization$key);

  const hiddenTypesOrganization = organization?.default_hidden_types ?? [];

  return (
      <HiddenTypesChipList hiddenTypes={hiddenTypesOrganization}/>
  );
};

export default SettingsOrganizationHiddenTypesChipList;
