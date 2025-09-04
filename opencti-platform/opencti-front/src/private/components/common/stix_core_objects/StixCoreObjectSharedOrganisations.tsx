import React, { useState } from 'react';
import Button from '@mui/material/Button';
import { useFragment } from 'react-relay';
import { StixCoreObjectSharingListFragment$key } from '@components/common/stix_core_objects/__generated__/StixCoreObjectSharingListFragment.graphql';
import { objectOrganizationFragment } from '@components/common/stix_core_objects/StixCoreObjectSharingList';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import StixCoreObjectSharedOrganisationsDrawer from '../containers/StixCoreObjectSharedOrganisationsDrawer';

interface ContainerHeaderSharedProps {
  data: StixCoreObjectSharingListFragment$key
  disabled?: boolean
}

const StixCoreObjectSharedOrganisations = ({
  data,
  disabled,
}: ContainerHeaderSharedProps) => {
  const { t_i18n } = useFormatter();
  const [openSharedOrganizations, setOpenSharedOrganizations] = useState(false);
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);

  const {
    objectOrganization,
  } = useFragment<StixCoreObjectSharingListFragment$key>(objectOrganizationFragment, data);

  if (objectOrganization?.length === 0) {
    return (<div/>);
  }
  return (
    <React.Fragment>
      <Button
        size="small"
        variant="text"
        color={hasSetAccess ? 'primary' : 'inherit'}
        style={{
          cursor: hasSetAccess ? 'pointer' : 'default',
          marginRight: 10,
          whiteSpace: 'nowrap',
        }}
        sx={!hasSetAccess ? {
          '&.MuiButtonBase-root:hover': {
            bgcolor: 'transparent',
          },
        } : undefined}
        onClick={() => (hasSetAccess ? setOpenSharedOrganizations(true) : null)}
        disableRipple={!hasSetAccess}
      >
        {objectOrganization?.length} {t_i18n('Organizations')}
      </Button>
      {(hasSetAccess && openSharedOrganizations) && (
        <StixCoreObjectSharedOrganisationsDrawer
          data={data}
          open={openSharedOrganizations}
          onClose={() => setOpenSharedOrganizations(false)}
          disableEdit={disabled}
        />
      )}
    </React.Fragment>
  );
};

export default StixCoreObjectSharedOrganisations;
