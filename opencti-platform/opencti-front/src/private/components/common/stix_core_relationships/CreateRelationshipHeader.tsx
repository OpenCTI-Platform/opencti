import React, { FunctionComponent, useContext, useState } from 'react';
import { CreateRelationshipContext } from '@components/common/menus/CreateRelationshipContextProvider';
import { Button, Typography } from '@mui/material';
import StixDomainObjectCreation from '@components/common/stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '@components/observations/stix_cyber_observables/StixCyberObservableCreation';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes } from '../../../../utils/stixTypeUtils';
import { useFormatter } from '../../../../components/i18n';
import { PaginationOptions } from '../../../../components/list_lines';

interface CreateRelationshipHeaderProps {
  showCreates: boolean,
  searchPaginationOptions?: PaginationOptions,
}

// Custom header prop for entity/observable creation buttons in initial step
const CreateRelationshipHeader: FunctionComponent<CreateRelationshipHeaderProps> = ({
  showCreates,
  searchPaginationOptions,
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
      {showCreates
        && <div>
          {showSDOCreation && (
            <Button
              onClick={handleOpenCreateEntity}
              variant='outlined'
              disableElevation
              size='small'
              aria-label={t_i18n('Create an entity')}
              style={{
                marginLeft: '3px',
                marginRight: showSCOCreation ? undefined : '15px',
                fontSize: 'small',
              }}
            >
              {t_i18n('Create an entity')}
            </Button>
          )}
          {showSCOCreation && (
            <Button
              onClick={handleOpenCreateObservable}
              variant='outlined'
              disableElevation
              size='small'
              aria-label={t_i18n('Create an observable')}
              style={{
                marginLeft: '3px',
                marginRight: '15px',
                fontSize: 'small',
              }}
            >
              {t_i18n('Create an observable')}
            </Button>
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
      }
    </div>
  );
};

export default CreateRelationshipHeader;
