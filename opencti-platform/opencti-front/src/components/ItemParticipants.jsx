import React from 'react';
import * as PropTypes from 'prop-types';
import Button from '@mui/material/Button';
import * as R from 'ramda';

const ItemParticipants = (props) => {
  const { participantsEdges } = props;
  const sortBy = R.sortWith([R.ascend(R.prop('name'))]);
  const participants = R.pipe(
    R.map((n) => n.node),
    sortBy,
  )(participantsEdges);
  return (
    <div>
      {participants.length > 0
        ? participants.map((assignee) => (
            <Button
              key={assignee.id}
              variant="outlined"
              color="primary"
              size="small"
              style={{ margin: '0 7px 7px 0', cursor: 'default' }}
            >
              {assignee.name}
            </Button>
        ))
        : '-'}
    </div>
  );
};

ItemParticipants.propTypes = {
  participantsEdges: PropTypes.object,
};

export default ItemParticipants;
