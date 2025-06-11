import React, { useState } from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import StixCoreObjectSharingList from '../../common/stix_core_objects/StixCoreObjectSharingList';
import { DraftChip } from '../../common/draft/DraftChip';
import StixCoreObjectEnrollPlaybook from '../../common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectContainer from '../../common/stix_core_objects/StixCoreObjectContainer';
import { truncate } from '../../../../utils/String';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectSharing from '../../common/stix_core_objects/StixCoreObjectSharing';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCyberObservableEdition from './StixCyberObservableEdition';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import PopoverMenu from '../../../../components/PopoverMenu';
import useSharingDisabled from '../../../../utils/hooks/useSharingDisabled';

const StixCyberObservableHeaderComponent = ({ stixCyberObservable }) => {
  const { t_i18n } = useFormatter();
  const [openSharing, setOpenSharing] = useState(false);

  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]);
  const isKnowledgeEnricher = useGranted([KNOWLEDGE_KNENRICHMENT]);

  const { isSharingNotPossible, sharingNotPossibleMessage } = useSharingDisabled(stixCyberObservable, false);

  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      <Typography variant="h1" sx={{ marginBottom: 0, flex: 1 }}>
        {truncate(stixCyberObservable.observable_value, 50)}
      </Typography>

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
                <Tooltip title={sharingNotPossibleMessage}>
                  <span>
                    <MenuItem
                      onClick={() => {
                        setOpenSharing(true);
                        closeMenu();
                      }}
                      disabled={isSharingNotPossible}
                    >
                      {t_i18n('Share with an organization')}
                    </MenuItem>
                  </span>
                </Tooltip>
              </Box>
            )}
          </PopoverMenu>

          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCyberObservableEdition
              stixCyberObservableId={stixCyberObservable.id}
            />
          </Security>

          <StixCoreObjectSharing
            elementId={stixCyberObservable.id}
            open={openSharing}
            variant="header"
            handleClose={() => setOpenSharing(false)}
          />
        </div>
      </div>
      <div className="clearfix" />
    </div>
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
