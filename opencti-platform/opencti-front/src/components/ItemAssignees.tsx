import React, { FunctionComponent } from 'react';
import Button from '@mui/material/Button';

type Node = {
  readonly entity_type: string;
  readonly id: string;
  readonly name: string;
};

type Props = {
  assignees: ReadonlyArray<Node>;
};

const ItemAssignees: FunctionComponent<Props> = ({ assignees }) => {
  return (
    <div>
      {assignees.length > 0
        ? assignees.map((assignee) => (
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
