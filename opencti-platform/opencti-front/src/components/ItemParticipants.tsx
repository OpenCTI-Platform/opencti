import React, { FunctionComponent } from 'react';
import FieldOrEmpty from './FieldOrEmpty';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../utils/hooks/useGranted';
import { truncate } from '../utils/String';
import { hexToRGB } from '../utils/Colors';
import { CancelOutlined } from '@mui/icons-material';
import Chip from '@mui/material/Chip';

interface ItemParticipantsProps {
  participants: {
    readonly entity_type: string
    readonly id: string
    readonly name: string
  }[];
}

const ItemParticipants: FunctionComponent<ItemParticipantsProps> = ({ participants }) => {
  const theme = useTheme<Theme>();
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);
  const handleRemoveParticipant = (participantId: string) => {
    console.log(participantId);
    // TODO : Mutation
  };
  return (
    <FieldOrEmpty source={participants}>
      {participants.map((participant) => (
        <Chip
          key={participant.id}
          variant="outlined"
          label={truncate(participant.name, 25)}
          style={{
            color: theme.palette.primary.main,
            borderColor: theme.palette.primary.main,
            backgroundColor: hexToRGB(theme.palette.primary.main),
            margin: '0 7px 7px 0',
            borderRadius: theme.borderRadius,
          }}
          onDelete={canUpdateKnowledge ? () => (handleRemoveParticipant(participant.id)) : undefined}
          deleteIcon={
            <CancelOutlined
              style={{ color: theme.palette.primary.main }}
            />
          }
        />
      ))}
    </FieldOrEmpty>
  );
};
export default ItemParticipants;
