import React, { FunctionComponent } from 'react';
import Button from '@mui/material/Button';
import FieldOrEmpty from './FieldOrEmpty';

interface ItemParticipantsProps {
  participants: {
    readonly entity_type: string
    readonly id: string
    readonly name: string
  }[];
}

const ItemParticipants: FunctionComponent<ItemParticipantsProps> = ({ participants }) => {
  return (
    <FieldOrEmpty source={participants}>
      {participants.map((participant) => (
        <Button
          key={participant.id}
          variant="outlined"
          color="primary"
          size="small"
          style={{ margin: '0 7px 7px 0', cursor: 'default' }}
        >
          {participant.name}
        </Button>
      ))}
    </FieldOrEmpty>
  );
};
export default ItemParticipants;
