import Button from '@common/button/Button';
import { Box, Tooltip } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import { useTheme } from '@mui/material/styles';
import { truncate } from '../../../../utils/String';
import PopoverMenu from '../../../../components/PopoverMenu';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';

interface StixSightingRelationshipHeaderProps {
  headerName?: string;
  onOpenDelete: () => void;
  onOpenEdit: () => void;
}

const StixSightingRelationshipHeader = ({
  headerName,
  onOpenDelete,
  onOpenEdit,
}: StixSightingRelationshipHeaderProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  // Remove CRUD button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canEdit = !draftContext || currentAccessRight.canEdit;
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]) && canEdit;

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
          <TitleMainEntity>
            {truncate(headerName, 80)}
          </TitleMainEntity>
        </Tooltip>
      </div>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        {canDelete && (
          <PopoverMenu>
            {({ closeMenu }) => (
              <Box>
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
