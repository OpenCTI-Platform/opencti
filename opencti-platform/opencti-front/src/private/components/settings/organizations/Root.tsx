import React, { FunctionComponent } from 'react';
import { useParams } from 'react-router-dom';
import TopBar from '../../nav/TopBar';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

interface RootSettingsOrganizationComponentProps {
  // queryRef: PreloadedQuery<RootSettingsOrganizationQuery>,
  organizationId: string,
}
const RootSettingsOrganizationComponent: FunctionComponent<RootSettingsOrganizationComponentProps> = ({  organizationId }) => {
  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      <div>
        Organization {organizationId}
      </div>
    </Security>
  );
};
const RootSettingsOrganization = () => {
  const { organizationId } = useParams() as { organizationId: string };
  // TODO Add queryRef
  return (
    <div>
      <TopBar />
      <RootSettingsOrganizationComponent organizationId={organizationId}/>
    </div>
  );
};
export default RootSettingsOrganization;
