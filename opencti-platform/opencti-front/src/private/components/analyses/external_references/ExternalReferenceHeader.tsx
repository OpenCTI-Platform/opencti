import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Box, Stack } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import ExternalReferenceDeletion from '@components/analyses/external_references/ExternalReferenceDeletion';
import { truncate } from '../../../../utils/String';
import { ExternalReferenceHeader_externalReference$data } from './__generated__/ExternalReferenceHeader_externalReference.graphql';
import PopoverMenu from '../../../../components/PopoverMenu';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { AUTOMATION, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';
import StixCoreObjectMenuItemUnderEE from '@components/common/stix_core_objects/StixCoreObjectMenuItemUnderEE';
import StixCoreObjectEnrollPlaybook from '@components/common/stix_core_objects/StixCoreObjectEnrollPlaybook';

interface ExternalReferenceHeaderComponentProps {
  externalReference: ExternalReferenceHeader_externalReference$data;
  EditComponent?: React.JSX.Element | boolean;
  enableEnrollPlaybook?: boolean;
}

const ExternalReferenceHeaderComponent = ({
  externalReference,
  EditComponent,
  enableEnrollPlaybook,
}: ExternalReferenceHeaderComponentProps) => {
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const { t_i18n } = useFormatter();
  const [openDelete, setOpenDelete] = useState(false);
  const [openEnrollPlaybook, setOpenEnrollPlaybook] = useState(false);

  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);
  const handleCloseEnrollPlaybook = () => {
    setOpenEnrollPlaybook(false);
  };
  const displayPopoverMenu = canDelete || enableEnrollPlaybook;

  return (
    <Stack direction="row" justifyContent="space-between" marginBottom={3}>
      <TitleMainEntity>
        {truncate(externalReference.source_name, 80)}
      </TitleMainEntity>
      <Stack direction="row" gap={1}>
        {enableEnrollPlaybook
          && (
            <StixCoreObjectEnrollPlaybook
              stixCoreObjectId={externalReference.id}
              open={openEnrollPlaybook}
              handleClose={handleCloseEnrollPlaybook}
            />
          )
        }
        {displayPopoverMenu && (
          <PopoverMenu>
            {({ closeMenu }) => (
              <Box>{enableEnrollPlaybook && (
                <StixCoreObjectMenuItemUnderEE
                  title={t_i18n('Enroll in playbook')}
                  setOpen={setOpenEnrollPlaybook}
                  handleCloseMenu={closeMenu}
                  needs={[AUTOMATION]}
                  matchAll
                />
              )}
              {canDelete && (
                <MenuItem onClick={() => {
                  handleOpenDelete();
                  closeMenu();
                }}
                >
                  {t_i18n('Delete')}
                </MenuItem>
              )}
              </Box>
            )}
          </PopoverMenu>
        )}
        {EditComponent}
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <ExternalReferenceDeletion
            id={externalReference.id}
            isOpen={openDelete}
            handleClose={handleCloseDelete}
          />
        </Security>
      </Stack>
    </Stack>
  );
};

const ExternalReferenceHeader = createFragmentContainer(
  ExternalReferenceHeaderComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceHeader_externalReference on ExternalReference {
        id
        source_name
        description
      }
    `,
  },
);

export default ExternalReferenceHeader;
