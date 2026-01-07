import { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import MenuItem from '@mui/material/MenuItem';
import StixCoreObjectSharingList from '../../common/stix_core_objects/StixCoreObjectSharingList';
import { DraftChip } from '../../common/draft/DraftChip';
import StixCoreObjectEnrollPlaybook from '../../common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectContainer from '../../common/stix_core_objects/StixCoreObjectContainer';
import { truncate } from '../../../../utils/String';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectSharing from '../../common/stix_core_objects/StixCoreObjectSharing';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from '../../../../utils/hooks/useGranted';
import StixCyberObservableEdition from './StixCyberObservableEdition';
import Security from '../../../../utils/Security';
import PopoverMenu from '../../../../components/PopoverMenu';
import StixCoreObjectMenuItemUnderEE from '../../common/stix_core_objects/StixCoreObjectMenuItemUnderEE';
import { useFormatter } from '../../../../components/i18n';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';
import { Stack } from '@mui/material';

const StixCyberObservableHeaderComponent = ({ stixCyberObservable, DeleteComponent }) => {
  const [openSharing, setOpenSharing] = useState(false);
  const [openDelete, setOpenDelete] = useState(false);
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const currentDraftAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canEdit = !draftContext || currentDraftAccessRight.canEdit;

  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]) && canEdit;
  const isKnowledgeEnricher = useGranted([KNOWLEDGE_KNENRICHMENT]) && canEdit;
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]) && canEdit;

  const handleOpenDelete = () => setOpenDelete(true);

  const handleCloseDelete = () => setOpenDelete(false);

  return (
    <Stack direction="row" alignItems="center" marginBottom={3}>
      <TitleMainEntity sx={{ flex: 1 }}>
        {truncate(stixCyberObservable.observable_value, 50)}
      </TitleMainEntity>

      {stixCyberObservable.draftVersion && <DraftChip />}

      <div>
        <div style={{ display: 'flex' }}>
          <StixCoreObjectSharingList data={stixCyberObservable} />

          {isKnowledgeUpdater && (
            <StixCoreObjectContainer elementId={stixCyberObservable.id} />
          )}
          {isKnowledgeEnricher && (
            <StixCoreObjectEnrichment stixCoreObjectId={stixCyberObservable.id} />
          )}
          <StixCoreObjectEnrollPlaybook stixCoreObjectId={stixCyberObservable.id} />

          <PopoverMenu>
            {({ closeMenu }) => (
              <Box>
                <StixCoreObjectMenuItemUnderEE
                  setOpen={setOpenSharing}
                  title={t_i18n('Share with an organization')}
                  handleCloseMenu={closeMenu}
                  needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}
                />
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
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCyberObservableEdition
              stixCyberObservableId={stixCyberObservable.id}
            />
          </Security>
          <DeleteComponent isOpen={openDelete} onClose={handleCloseDelete} />

          <StixCoreObjectSharing
            elementId={stixCyberObservable.id}
            open={openSharing}
            variant="header"
            handleClose={() => setOpenSharing(false)}
          />
        </div>
      </div>
      <div className="clearfix" />
    </Stack>
  );
};

const StixCyberObservableHeader = createFragmentContainer(
  StixCyberObservableHeaderComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableHeader_stixCyberObservable on StixCyberObservable {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        entity_type
        observable_value
        ...StixCoreObjectSharingListFragment
      }
    `,
  },
);

export default StixCyberObservableHeader;
