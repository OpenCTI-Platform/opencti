import { Box } from '@mui/material';
import { IconButton, Menu, MenuContent, MenuItem, MenuTrigger } from '@filigran/design-system';
import { ArrowDropDownOutlined } from '@mui/icons-material';
import Button from '../../../../../components/common/button/Button';
import { useFormatter } from '../../../../../components/i18n';

interface SecurityCoverageResultsDropdownProps {
  onCreate: () => void;
  onUpdate: () => void;
  canUpdate: boolean;
}

const SecurityCoverageResultsDropdown = ({
  onCreate,
  onUpdate,
  canUpdate,
}: SecurityCoverageResultsDropdownProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Box
      id="security-coverage-result-split-button"
      sx={{
        display: 'flex',
        alignItems: 'center',
        '& > button:first-of-type': {
          borderTopRightRadius: 0,
          borderBottomRightRadius: 0,
        },
        '& > button:last-of-type': {
          borderTopLeftRadius: 0,
          borderBottomLeftRadius: 0,
          marginLeft: '-1px',
        },
      }}
    >
      <Button variant="secondary" onClick={onCreate}>
        {t_i18n('Add manual Coverage Result')}
      </Button>
      <Menu>
        <MenuTrigger asChild>
          <IconButton
            priority="secondary"
            icon={<ArrowDropDownOutlined fontSize="small" />}
            aria-label={t_i18n('Open menu')}
            disabled={!canUpdate}
          />
        </MenuTrigger>
        <MenuContent align="end" sideOffset={6}>
          <MenuItem onSelect={onUpdate}>
            {t_i18n('Update existing Security Coverage Result')}
          </MenuItem>
        </MenuContent>
      </Menu>
    </Box>
  );
};

export default SecurityCoverageResultsDropdown;
