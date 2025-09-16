import React from 'react';
import { Link } from 'react-router-dom';
import Button from '@mui/material/Button';
import { resolveLink } from '../utils/Entity';

interface ItemAuthorProps {
  createdBy: {
    id: string,
    name: string,
    entity_type: string,
  } | null | undefined
}

const ItemAuthor = ({ createdBy }: ItemAuthorProps) => {
  return (
    <>
      {createdBy ? (
        <Button
          variant="outlined"
          color="primary"
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
