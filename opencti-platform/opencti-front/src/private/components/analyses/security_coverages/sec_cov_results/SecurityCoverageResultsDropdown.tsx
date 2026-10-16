import { useState } from 'react';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@filigran/design-system';
import { ArrowDropDownOutlined, ArrowDropUpOutlined } from '@mui/icons-material';
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
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <Menu open={menuOpen} onOpenChange={setMenuOpen}>
      <MenuTrigger asChild>
        <Button
          variant="secondary"
          endIcon={menuOpen ? <ArrowDropUpOutlined /> : <ArrowDropDownOutlined />}
        >
          {t_i18n('Add manual Coverage Result')}
        </Button>
      </MenuTrigger>
      <MenuContent align="end" sideOffset={6}>
        <MenuItem onSelect={onCreate}>
          {t_i18n('Add new Security Coverage Result')}
        </MenuItem>
        <MenuItem onSelect={onUpdate} disabled={!canUpdate}>
          {t_i18n('Update existing Security Coverage Result')}
        </MenuItem>
      </MenuContent>
    </Menu>
  );
};

export default SecurityCoverageResultsDropdown;
