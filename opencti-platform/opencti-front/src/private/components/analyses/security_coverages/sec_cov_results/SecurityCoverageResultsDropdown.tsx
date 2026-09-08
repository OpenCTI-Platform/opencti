import Button from '../../../../../components/common/button/Button';
import { useFormatter } from '../../../../../components/i18n';

interface SecurityCoverageResultsDropdownProps {
  onCreate: () => void;
}

const SecurityCoverageResultsDropdown = ({
  onCreate,
}: SecurityCoverageResultsDropdownProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Button variant="secondary" onClick={onCreate}>
      {t_i18n('Add manual Coverage Result')}
    </Button>
  );
};

export default SecurityCoverageResultsDropdown;
