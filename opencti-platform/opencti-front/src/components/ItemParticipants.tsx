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
  const participantsData = (participants ?? []).slice()
    .sort((a, b) => a.name.localeCompare(b.name));

  return (
    <FieldOrEmpty source={participantsData}>
      {participantsData.map((participant) => (
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
