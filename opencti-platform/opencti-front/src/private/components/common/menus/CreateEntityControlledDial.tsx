import React from 'react';
import { Add } from '@mui/icons-material';
import { Button, styled } from '@mui/material';
import { useFormatter } from 'src/components/i18n';

export const StyledCreateButton = styled(Button)({
  marginLeft: '10px',
  padding: '7px 10px',
});

const CreateEntityControlledDial = (entity_type: string) => {
  const { t_i18n } = useFormatter();
  const controlledDial = ({ onOpen }: {
    onOpen: () => void
  }) => (
    <StyledCreateButton
      onClick={onOpen}
      color='primary'
      size='small'
      variant='contained'
    >
      {t_i18n('Create')} {t_i18n(entity_type)} <Add />
    </StyledCreateButton>
  );
  return controlledDial;
};

export default CreateEntityControlledDial;