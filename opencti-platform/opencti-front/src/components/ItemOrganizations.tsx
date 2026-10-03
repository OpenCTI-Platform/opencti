import { AccountBalanceOutlined } from '@mui/icons-material';
import Tag from '@common/tag/Tag';

interface ItemOrganizationsProps {
  organizationName: string;
  organizationId: string;
  removeOrganization: (id: string) => void;
  disabled?: boolean;
}

const ItemOrganizations = ({
  organizationName,
  organizationId,
  removeOrganization,
  disabled,
}: ItemOrganizationsProps) => {
  return (
    <Tag
      label={organizationName}
      onDelete={() => removeOrganization(organizationId)}
      disabled={disabled}
      icon={<AccountBalanceOutlined fontSize="small" />}
      maxWidth={150}
    />
  );
};

export default ItemOrganizations;
