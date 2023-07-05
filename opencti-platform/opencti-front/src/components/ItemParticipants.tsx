import { FunctionComponent } from 'react';
import Button from '@mui/material/Button';

interface ItemParticipantsProps {
  // TODO To fix tomorrow :)
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  participantsEdges: any[];
}

const ItemParticipants: FunctionComponent<ItemParticipantsProps> = ({
  participantsEdges,
}) => {
  const participants = participantsEdges.slice()
    .sort((a, b) => a.node.name.localeCompare(b.node.name))
    .map((n) => n.node);

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
export default ItemParticipants;
