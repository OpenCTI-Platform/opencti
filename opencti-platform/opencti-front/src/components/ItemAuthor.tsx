import React from 'react';
import { Link } from 'react-router-dom';
import Button from '@common/button/Button';
import { resolveLink } from '../utils/Entity';

interface ItemAuthorProps {
  createdBy: {
    id: string;
    name: string;
    entity_type: string;
  } | null | undefined;
}

const ItemAuthor = ({ createdBy }: ItemAuthorProps) => {
  return (
    <>
      {createdBy ? (
        <Button
          variant="secondary"
          size="small"
          component={Link}
          to={`${resolveLink(createdBy.entity_type)}/${
            createdBy.id
          }?viewAs=author`}
        >
          {createdBy.name}
        </Button>
      ) : (
        '-'
      )}
    </>
  );
};

export default ItemAuthor;
