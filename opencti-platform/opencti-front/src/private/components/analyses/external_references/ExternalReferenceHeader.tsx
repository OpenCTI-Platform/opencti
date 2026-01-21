import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Box, Stack } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import ExternalReferenceDeletion from '@components/analyses/external_references/ExternalReferenceDeletion';
import { truncate } from '../../../../utils/String';
import { ExternalReferenceHeader_externalReference$data } from './__generated__/ExternalReferenceHeader_externalReference.graphql';
import PopoverMenu from '../../../../components/PopoverMenu';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';

interface ExternalReferenceHeaderComponentProps {
  externalReference: ExternalReferenceHeader_externalReference$data;
  EditComponent?: React.JSX.Element | boolean;
}

const ExternalReferenceHeaderComponent = ({
  externalReference,
  EditComponent,
}: ExternalReferenceHeaderComponentProps) => {
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const { t_i18n } = useFormatter();
  const [openDelete, setOpenDelete] = useState(false);
  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  return (
    <Stack direction="row" justifyContent="space-between" marginBottom={3}>
      <TitleMainEntity>
        {truncate(externalReference.source_name, 80)}
      </TitleMainEntity>
      <Stack direction="row" gap={1}>
        {canDelete && (
          <PopoverMenu>
            {({ closeMenu }) => (
              <Box>
                <MenuItem onClick={() => {
                  handleOpenDelete();
                  closeMenu();
                }}
                >
                  {t_i18n('Delete')}
                </MenuItem>
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
