import React, { FunctionComponent } from 'react';
import Button from '@mui/material/Button';
import * as R from 'ramda';

type Node = {
  readonly entity_type: string;
  readonly id: string;
  readonly name: string;
};

type Props = {
  assignees: ReadonlyArray<Node>;
};

const ItemAssignees: FunctionComponent<Props> = (props) => {
  const { assignees } = props;
  const sortBy = R.sortWith([R.ascend<Node>(R.prop('name'))]);
  const sortedAssignees = R.pipe(sortBy)(assignees);
  return (
    <div>
      {sortedAssignees.length > 0
        ? sortedAssignees.map((assignee) => (
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

export default ItemAssignees;
