import { UIEvent, useState } from 'react';
import stopEvent from '../domEvent';

export interface Deletion {
  deleting: boolean
  handleOpenDelete: (e?: UIEvent) => void;
  displayDelete: boolean
  handleCloseDelete: (e?: UIEvent) => void;
  setDeleting: (value: (((prevState: boolean) => boolean) | boolean)) => void
}

const useDeletion = ({ handleClose }: { handleClose?: () => void }): Deletion => {
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);

  const handleOpenDelete = (e?: UIEvent) => {
    if (e) stopEvent(e);
    setDisplayDelete(true);
    handleClose?.();
  };

  const handleCloseDelete = (e?: UIEvent) => {
    if (e) stopEvent(e);
    setDisplayDelete(false);
  };

  return {
    deleting,
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
    setDeleting,
  };
};

export default useDeletion;
