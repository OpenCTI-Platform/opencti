import { useState } from 'react';

export interface Deletion {
  deleting: boolean
  handleOpenDelete: () => void
  displayDelete: boolean
  handleCloseDelete: () => void
  setDeleting: (value: (((prevState: boolean) => boolean) | boolean)) => void
}

const useDeletion = ({ handleClose }: { handleClose: () => void }) => {
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => {
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
