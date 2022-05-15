import React from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import Button from '@mui/material/Button';
import { resolveLink } from '../utils/Entity';

const ItemAuthor = (props) => {
  const { createdBy } = props;
  return (
    <div>
      {createdBy ? (
        <Button
          variant="outlined"
          color="secondary"
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
    </div>
  );
};

ItemAuthor.propTypes = {
  createdBy: PropTypes.object,
};

export default ItemAuthor;
