import { useState } from 'react';

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
