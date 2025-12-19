import React, { useState } from 'react';
import Button from '@common/button/Button';
import BulkRelationDialog from '@components/common/bulk/dialog/BulkRelationDialog';
import { PaginationOptions } from 'src/components/list_lines';
import { useFormatter } from 'src/components/i18n';
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
  onBulkCreate: () => void;
};

const inlinedStyle = {
  button: {
    display: 'flex',
    float: 'right',
    alignItems: 'center',
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
  onBulkCreate,
}: BulkRelationDialogContainerProps) => {
  const { t_i18n } = useFormatter();

  const [isDialogOpen, setIsDialogOpen] = useState<boolean>(false);

  const handleOpenDialog = () => setIsDialogOpen(true);

  const handleCloseDialog = () => setIsDialogOpen(false);

  return (
    <>
      <Button onClick={handleOpenDialog} variant="secondary" sx={inlinedStyle.button} size="small">
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
          onBulkCreate={onBulkCreate}
        />
      )}
    </>
  );
};

export default BulkRelationDialogContainer;
