import Tag from '@common/tag/Tag';
import { useNavigate } from 'react-router-dom';
import { resolveLink } from '../utils/Entity';
import { EMPTY_VALUE } from '../utils/String';

interface ItemAuthorProps {
  createdBy: {
    id: string;
    name: string;
    entity_type: string;
  } | null | undefined;
}

const ItemAuthor = ({ createdBy }: ItemAuthorProps) => {
  const navigate = useNavigate();

  const URL = createdBy ? `${resolveLink(createdBy.entity_type)}/${createdBy.id}?viewAs=author` : null;
  return (
    <>
      {createdBy ? (
        <Tag
          label={createdBy.name}
          {...!!URL && { onClick: () => navigate(URL) }}
        />
      ) : (
        EMPTY_VALUE
      )}
    </>
  );
};

export default ItemAuthor;
