import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Button from '@material-ui/core/Button';
import { Link } from 'react-router-dom';
class ItemCreator extends Component {
  render() {
    const { creator } = this.props;
    return (
      <div>
        {creator ? (
          <Button
            variant="outlined"
            size="small"
            component={Link}
            to={`/dashboard/entities/persons/${creator.id}?viewAs=author`}
          >
            {creator.name}
          </Button>
        ) : (
          '-'
        )}
      </div>
    );
  }
}

ItemCreator.propTypes = {
  creator: PropTypes.object,
};

export default ItemCreator;
