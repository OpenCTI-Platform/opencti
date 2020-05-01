import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import Button from '@material-ui/core/Button';
import { resolveLink } from '../utils/Entity';

class ItemAuthor extends Component {
  render() {
    const { createdByRef } = this.props;
    return (
      <div>
        {createdByRef ? (
          <Button
            variant="outlined"
            color="secondary"
            size="small"
            component={Link}
            to={`${resolveLink(createdByRef.entity_type)}/${createdByRef.id}?viewAs=author`}
          >
            {createdByRef.name}
          </Button>
        ) : (
          '-'
        )}
      </div>
    );
  }
}

ItemAuthor.propTypes = {
  createdByRef: PropTypes.object,
};

export default ItemAuthor;
