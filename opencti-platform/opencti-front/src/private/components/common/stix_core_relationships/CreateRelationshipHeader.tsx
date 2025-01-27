import React, { FunctionComponent, useContext, useState } from 'react';
import { CreateRelationshipContext } from '@components/common/menus/CreateRelationshipContextProvider';
import { Button, Typography } from '@mui/material';
import StixDomainObjectCreation from '@components/common/stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '@components/observations/stix_cyber_observables/StixCyberObservableCreation';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes } from '../../../../utils/stixTypeUtils';
import { useFormatter } from '../../../../components/i18n';
import { PaginationOptions } from '../../../../components/list_lines';
import BulkRelationDialogContainer from '../bulk/dialog/BulkRelationDialogContainer';
import { TargetEntity } from './StixCoreRelationshipCreationFromEntity';

export interface HeaderOpts {
  stixDomainObjectId: string,
  stixDomainObjectName: string,
  stixDomainObjectType: string,
  selectedEntities: TargetEntity[],
}

interface CreateRelationshipHeaderProps {
  showCreates: boolean,
  searchPaginationOptions?: PaginationOptions,
  bulkDialogOptions?: HeaderOpts,
}

// Custom header prop for entity/observable creation buttons in initial step
const CreateRelationshipHeader: FunctionComponent<CreateRelationshipHeaderProps> = ({
  showCreates,
  searchPaginationOptions,
  bulkDialogOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [openCreateEntity, setOpenCreateEntity] = useState<boolean>(false);
  const [openCreateObservable, setOpenCreateObservable] = useState<boolean>(false);
  const { state: { stixCoreObjectTypes } } = useContext(CreateRelationshipContext);
  const targetEntityTypes = (stixCoreObjectTypes ?? []).length > 0 ? stixCoreObjectTypes ?? ['Stix-Core-Object'] : ['Stix-Core-Object'];
  const targetStixDomainObjectTypes = computeTargetStixDomainObjectTypes(targetEntityTypes);
  const targetStixCyberObservableTypes = computeTargetStixCyberObservableTypes(targetEntityTypes);
  const showSDOCreation = targetStixDomainObjectTypes.length > 0;
  const showSCOCreation = targetStixCyberObservableTypes.length > 0;

  const handleOpenCreateEntity = () => setOpenCreateEntity(true);
  const handleCloseCreateEntity = () => setOpenCreateEntity(false);
  const handleOpenCreateObservable = () => setOpenCreateObservable(true);
  const handleCloseCreateObservable = () => setOpenCreateObservable(false);

  const entityTypes = [
    ...targetStixDomainObjectTypes,
    ...targetStixCyberObservableTypes,
  ];

  return (
    <div style={{
      width: '100%',
      display: 'flex',
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
    }}
    >
      <Typography variant='subtitle2'>{t_i18n('Create a relationship')}</Typography>
      {showCreates && (
        <div style={{
          display: 'flex',
          flexDirection: 'row',
          justifyContent: 'space-between',
          gap: '3px',
          marginRight: '15px',
        }}
        >
          {showSDOCreation && (
            <Button
              onClick={handleOpenCreateEntity}
              variant='outlined'
              disableElevation
              size='small'
              aria-label={t_i18n('Create entity')}
              style={{ fontSize: 'small' }}
            >
              {t_i18n('Create entity')}
            </Button>
          )}
          {showSCOCreation && (
            <Button
              onClick={handleOpenCreateObservable}
              variant='outlined'
              disableElevation
              size='small'
              aria-label={t_i18n('Create observable')}
              style={{ fontSize: 'small' }}
            >
              {t_i18n('Create observable')}
            </Button>
          )}
          {bulkDialogOptions && (
            <BulkRelationDialogContainer
              targetObjectTypes={['Stix-Domain-Object', 'Stix-Cyber-Observable']}
              paginationOptions={searchPaginationOptions ?? {}}
              paginationKey="Pagination_stixCoreObjects"
              key="BulkRelationDialogContainer"
              stixDomainObjectId={bulkDialogOptions.stixDomainObjectId}
              stixDomainObjectName={bulkDialogOptions.stixDomainObjectName}
              stixDomainObjectType={bulkDialogOptions.stixDomainObjectType}
              selectedEntities={bulkDialogOptions.selectedEntities}
              variant={'contained'}
            />
          )}
          <StixDomainObjectCreation
            display={true}
            inputValue={''}
            paginationKey="Pagination_stixCoreObjects"
            paginationOptions={searchPaginationOptions}
            speeddial={true}
            open={openCreateEntity}
            handleClose={handleCloseCreateEntity}
            creationCallback={undefined}
            confidence={undefined}
            defaultCreatedBy={undefined}
            defaultMarkingDefinitions={undefined}
            stixDomainObjectTypes={entityTypes}
            onCompleted={undefined}
            isFromBulkRelation={undefined}
          />
          <StixCyberObservableCreation
            display={true}
            contextual={true}
            inputValue={''}
            paginationKey="Pagination_stixCoreObjects"
            paginationOptions={searchPaginationOptions}
            speeddial={true}
            open={openCreateObservable}
            handleClose={handleCloseCreateObservable}
            type={undefined}
            isFromBulkRelation={undefined}
            onCompleted={undefined}
          />
        </div>
      )}
    </div>
  );
};

export default CreateRelationshipHeader;
