import React, { useState } from 'react';
import Button from '@mui/material/Button';
import BulkRelationDialog from '@components/common/bulk/dialog/BulkRelationDialog';
import { useFormatter } from 'src/components/i18n';
import useHelper from 'src/utils/hooks/useHelper';

type BulkRelationDialogContainerProps = {
  stixDomainObjectId: string;
  stixDomainObjectName: string;
  stixDomainObjectType: string;
  handleRefetch: () => void;
};

const inlinedStyle = {
  button: {
    display: 'flex',
    margin: '-45px 0px 0 0',
    float: 'right',
    alignItems: 'center',
  },
};
const BulkRelationDialogContainer = ({ stixDomainObjectId, stixDomainObjectName, stixDomainObjectType, handleRefetch }: BulkRelationDialogContainerProps) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();

  const BULK_RELATIONS_FF = isFeatureEnable('4352_BULK_RELATIONS');

  const [isDialogOpen, setIsDialogOpen] = useState<boolean>(false);

  const handleOpenDialog = () => setIsDialogOpen(true);

  const handleCloseDialog = () => setIsDialogOpen(false);

  if (!BULK_RELATIONS_FF) return null;

  return (
    <>
      <Button onClick={handleOpenDialog} variant="outlined" sx={inlinedStyle.button}>
        {t_i18n('Create bulk relations')}
      </Button>
      {isDialogOpen && (
      <BulkRelationDialog
        stixDomainObjectId={stixDomainObjectId}
        stixDomainObjectName={stixDomainObjectName}
        stixDomainObjectType={stixDomainObjectType}
        isOpen={isDialogOpen}
        onClose={handleCloseDialog}
        handleRefetch={handleRefetch}
      />
      )}
    </>
  );
};

export default BulkRelationDialogContainer;
