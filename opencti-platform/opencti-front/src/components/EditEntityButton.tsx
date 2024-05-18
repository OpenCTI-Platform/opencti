import React from 'react';
import { Button, styled } from '@mui/material';
import { Edit } from '@mui/icons-material';
import { useFormatter } from './i18n';

const EditEntityButton = ({ onOpen }: { onOpen: () => void }) => {
  const { t_i18n } = useFormatter();
  const StyledEditButton = styled(Button)({
    marginLeft: '3px',
  });
  return (
    <StyledEditButton
      onClick={onOpen}
      variant='contained'
      size='small'
    >
      {t_i18n('Edit')} <Edit fontSize='small' />
    </StyledEditButton>
  );
};

export default EditEntityButton;
