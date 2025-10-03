import { Box, Button, Tooltip } from '@mui/material';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import React from 'react';
import { useTheme } from '@mui/material/styles';
import { truncate } from '../../../../utils/String';
import PopoverMenu from '../../../../components/PopoverMenu';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

interface StixSightingRelationshipHeaderProps {
  headerName?: string,
  onOpenDelete: () => void,
  onOpenEdit: () => void,
}

const StixSightingRelationshipHeader = ({
  headerName,
  onOpenDelete,
  onOpenEdit,
}: StixSightingRelationshipHeaderProps) => {
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

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
        {(
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <Button
              variant='contained'
              size='medium'
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
