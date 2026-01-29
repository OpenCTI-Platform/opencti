import HeaderMainEntityLayout from '@common/header/HeaderMainEntityLayout';
import Box from '@mui/material/Box';
import MenuItem from '@mui/material/MenuItem';
import { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import PopoverMenu from '../../../../components/PopoverMenu';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { DraftChip } from '../../common/draft/DraftChip';
import StixCoreObjectContainer from '../../common/stix_core_objects/StixCoreObjectContainer';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectEnrollPlaybook from '../../common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectMenuItemUnderEE from '../../common/stix_core_objects/StixCoreObjectMenuItemUnderEE';
import StixCoreObjectSharing from '../../common/stix_core_objects/StixCoreObjectSharing';
import StixCoreObjectSharingList from '../../common/stix_core_objects/StixCoreObjectSharingList';
import StixCyberObservableEdition from './StixCyberObservableEdition';

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
    <HeaderMainEntityLayout
      title={stixCyberObservable.observable_value}
      rightActions={(
        <>
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
        </>
      )}
      leftTags={
        stixCyberObservable.draftVersion && <DraftChip />
      }
      rightTags={
        <StixCoreObjectSharingList data={stixCyberObservable} />
      }
    />
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
