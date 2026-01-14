import { Box, Button, Tooltip } from '@mui/material';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import React, { useState } from 'react';
import { useTheme } from '@mui/material/styles';
import { truncate } from '../../../../utils/String';
import PopoverMenu from '../../../../components/PopoverMenu';
import Security from '../../../../utils/Security';
import useGranted, { AUTOMATION, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import StixCoreObjectEnrollPlaybook from '@components/common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectMenuItemUnderEE from '@components/common/stix_core_objects/StixCoreObjectMenuItemUnderEE';

interface StixSightingRelationshipHeaderProps {
  headerName?: string;
  onOpenDelete: () => void;
  onOpenEdit: () => void;
  enableEnrollPlaybook?: boolean;
  stixSightingId: string;
}

const StixSightingRelationshipHeader = ({
  headerName,
  onOpenDelete,
  onOpenEdit,
  enableEnrollPlaybook,
  stixSightingId,
}: StixSightingRelationshipHeaderProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  // Remove CRUD button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canEdit = !draftContext || currentAccessRight.canEdit;
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]) && canEdit;
  const [openEnrollPlaybook, setOpenEnrollPlaybook] = useState(false);
  const handleCloseEnrollPlaybook = () => {
    setOpenEnrollPlaybook(false);
  };
  const displayEnrollPlaybook = enableEnrollPlaybook;
  console.log('stixSightingId', stixSightingId);

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: theme.spacing(3),
    }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
        <Tooltip title={headerName}>
          <Typography
            variant="h1"
            sx={{
              margin: 0,
              lineHeight: 'unset',
            }}
          >
            {truncate(headerName, 80)}
          </Typography>
        </Tooltip>
      </div>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        {displayEnrollPlaybook
          && (
            <StixCoreObjectEnrollPlaybook
              stixCoreObjectId={stixSightingId}
              open={openEnrollPlaybook}
              handleClose={handleCloseEnrollPlaybook}
            />
          )
        }
        {canDelete && (
          <PopoverMenu>
            {({ closeMenu }) => (
              <Box>
                {displayEnrollPlaybook && (
                  <StixCoreObjectMenuItemUnderEE
                    title={t_i18n('Enroll in playbook')}
                    setOpen={setOpenEnrollPlaybook}
                    handleCloseMenu={closeMenu}
                    needs={[AUTOMATION]}
                    matchAll
                  />
                )}
                <MenuItem onClick={() => {
                  onOpenDelete();
                  closeMenu();
                }}
                >
                  {t_i18n('Delete')}
                </MenuItem>
              </Box>
            )}
          </PopoverMenu>
        )}
        {canEdit && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <Button
              variant="contained"
              size="medium"
              aria-label={t_i18n('Update')}
              onClick={onOpenEdit}
              style={{ marginLeft: theme.spacing(0.5) }}
            >
              {t_i18n('Update')}
            </Button>
          </Security>
        )}
      </div>
    </div>
  );
};

export default StixSightingRelationshipHeader;
