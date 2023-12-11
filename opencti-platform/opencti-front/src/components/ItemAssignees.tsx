import React, { FunctionComponent } from 'react';
import Button from '@mui/material/Button';
import * as R from 'ramda';

type Node = {
  readonly entity_type: string;
  readonly id: string;
  readonly name: string;
};

type Props = {
  assigneesEdges: ReadonlyArray<{
    readonly node: Node;
  }>
};

const ItemAssignees: FunctionComponent<Props> = (props) => {
  const { assigneesEdges } = props;
  const sortBy = R.sortWith([R.ascend<Node>(R.prop('name'))]);
  const assignees = R.pipe(
    R.map((n: { node: Node }) => n.node),
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
