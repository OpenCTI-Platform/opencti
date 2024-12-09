import MoreVert from '@mui/icons-material/MoreVert';
import React, { UIEvent } from 'react';
import IconButton from '@mui/material/IconButton';
import stopEvent from '../../../../../utils/domEvent';

const FintelTemplatePopover = () => {
  const onClick = (e: UIEvent) => {
    stopEvent(e);
    console.log('TODO');
  };

  return (
    <>
      <IconButton
        onClick={onClick}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        color="primary"
      >
        <MoreVert />
      </IconButton>
    </>
  );
};

export default FintelTemplatePopover;
