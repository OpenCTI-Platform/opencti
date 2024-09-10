import React, { useState } from 'react';
import Button from '@mui/material/Button';
import BulkRelationDialog from '@components/common/bulk/dialog/BulkRelationDialog';
import { PaginationOptions } from 'src/components/list_lines';
import { useFormatter } from 'src/components/i18n';
import useHelper from 'src/utils/hooks/useHelper';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

type BulkRelationDialogContainerProps = {
  stixDomainObjectId: string;
  stixDomainObjectName: string;
  stixDomainObjectType: string;
  selectedEntities: TargetEntity[];
  defaultRelationshipType?: string;
  paginationKey: string;
  paginationOptions: PaginationOptions;
  targetObjectTypes: string[];
};

const inlinedStyle = {
  button: {
    display: 'flex',
    float: 'right',
    alignItems: 'center',
    margin: '0 10px',
  },
};
const BulkRelationDialogContainer = ({
  stixDomainObjectId,
  stixDomainObjectName,
  stixDomainObjectType,
  selectedEntities,
  defaultRelationshipType,
  paginationKey,
  paginationOptions,
  targetObjectTypes,
}: BulkRelationDialogContainerProps) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();

  const BULK_RELATIONS_FF = isFeatureEnable('4352_BULK_RELATIONS');

  const [isDialogOpen, setIsDialogOpen] = useState<boolean>(false);

  const handleOpenDialog = () => setIsDialogOpen(true);

  const handleCloseDialog = () => setIsDialogOpen(false);

  if (!BULK_RELATIONS_FF) return null;

  return (
    <>
      <Button onClick={handleOpenDialog} color="primary" variant="outlined" sx={inlinedStyle.button} size="small">
        {t_i18n('Create relations in bulk')}
      </Button>
      {isDialogOpen && (
        <BulkRelationDialog
          paginationKey={paginationKey}
          paginationOptions={paginationOptions}
          stixDomainObjectId={stixDomainObjectId}
          stixDomainObjectName={stixDomainObjectName}
          stixDomainObjectType={stixDomainObjectType}
          defaultRelationshipType={defaultRelationshipType}
          isOpen={isDialogOpen}
          targetObjectTypes={targetObjectTypes}
          onClose={handleCloseDialog}
          selectedEntities={selectedEntities}
        />
      )}
    </>
  );
};

export default BulkRelationDialogContainer;
