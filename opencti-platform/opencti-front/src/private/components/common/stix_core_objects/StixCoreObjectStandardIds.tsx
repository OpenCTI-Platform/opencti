import Label from '../../../../components/common/label/Label';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { BrushOutlined, Delete } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import ItemCopy from '../../../../components/ItemCopy';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { useState } from 'react';

interface StixCoreObjectStandardIdsProps {
  standardId: string;
  stixIds?: string[];
  deleteStixId?: (stixId: string) => void;
}

export const StixCoreObjectStandardIds = ({ standardId, stixIds = [], deleteStixId }: StixCoreObjectStandardIdsProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const [isStixIdsDialogOpen, setOpenStixIds] = useState(false);

  const handleToggleOpenStixIds = () => {
    setOpenStixIds((previousValue) => !previousValue);
  };

  const otherStixIds = stixIds.filter((n) => n !== standardId);

  return (
    <>
      <Label
        sx={{ marginTop: 2 }}
        action={(
          <>
            <Tooltip
              title={t_i18n(
                'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
              )}
            >
              <InformationOutline fontSize="small" color="primary" />
            </Tooltip>
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <IconButton
                variant="tertiary"
                aria-label="Close"
                size="small"
                disabled={otherStixIds.length === 0}
                onClick={handleToggleOpenStixIds}
              >
                <BrushOutlined
                  fontSize="small"
                  color={otherStixIds.length === 0 ? 'inherit' : 'primary'}
                />
              </IconButton>
            </Security>

          </>
        )}
      >
        {t_i18n('Standard STIX ID')}
      </Label>
      <div style={{
        padding: '5px 5px 5px 10px',
        fontFamily: 'Consolas, monaco, monospace',
        fontSize: 11,
        backgroundColor:
          theme.palette.mode === 'light'
            ? 'rgba(0, 0, 0, 0.02)'
            : 'rgba(255, 255, 255, 0.02)',
        lineHeight: '18px',
      }}
      >
        <ItemCopy content={standardId} />
      </div>
      <Dialog
        open={isStixIdsDialogOpen}
        onClose={handleToggleOpenStixIds}
        title={t_i18n('Other STIX IDs')}
      >
        <List>
          {stixIds.map(
            (stixId) => stixId.length > 0 && (
              <ListItem
                key={stixId}
                disableGutters={true}
                dense={true}
                secondaryAction={deleteStixId && (
                  <IconButton
                    aria-label="delete"
                    onClick={() => deleteStixId(stixId)}
                  >
                    <Delete />
                  </IconButton>
                )}
              >
                <ListItemText primary={stixId} />
              </ListItem>
            ),
          )}
        </List>
        <DialogActions>
          <Button
            onClick={handleToggleOpenStixIds}
          >
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};
