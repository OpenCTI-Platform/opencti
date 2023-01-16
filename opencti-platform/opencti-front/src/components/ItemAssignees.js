import React from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import Button from '@mui/material/Button';
import * as R from 'ramda';
import { resolveLink } from '../utils/Entity';

const ItemAssignees = (props) => {
  const { assigneesEdges } = props;
  const sortBy = R.sortWith([R.ascend(R.prop('name'))]);
  const assignees = R.pipe(
    R.map((n) => n.node),
    sortBy,
  )(assigneesEdges);
  return (
    <div>
      {assignees.length > 0
        ? assignees.map((assignee) => (
            <Button
              key={assignee.id}
              variant="outlined"
              color="primary"
              size="small"
              component={Link}
              to={`${resolveLink(assignee.entity_type)}/${
                assignee.id
              }?viewAs=author`}
              style={{ margin: '0 7px 7px 0' }}
            >
              {assignee.name}
            </Button>
        ))
        : '-'}
    </div>
  );
};

ItemAssignees.propTypes = {
  assigneesEdges: PropTypes.object,
};

export default ItemAssignees;
