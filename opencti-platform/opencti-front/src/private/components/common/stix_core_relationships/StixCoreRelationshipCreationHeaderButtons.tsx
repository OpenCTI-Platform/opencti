import React, { FunctionComponent, useContext, useState } from 'react';
import { Button } from '@mui/material';
import { CreateRelationshipContext } from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import { useFormatter } from '../../../../components/i18n';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import { PaginationOptions } from '../../../../components/list_lines';

interface StixCoreRelationshipCreationHeaderButtonsProps {
  show: boolean;
  showSDOs: boolean;
  showSCOs: boolean;
  actualTypeFilterValues: string[];
}

const StixCoreRelationshipCreationHeaderButtons: FunctionComponent<
StixCoreRelationshipCreationHeaderButtonsProps
> = ({
  show,
  showSDOs,
  showSCOs,
  actualTypeFilterValues,
}) => {
  const { t_i18n } = useFormatter();
  const [openCreateObservable, setOpenCreateObservable] = useState<boolean>(false);

  // Fetch from context
  const { state: { paginationOptions } } = useContext(CreateRelationshipContext);
  const searchPaginationOptions = paginationOptions as PaginationOptions;

  const handleOpenCreateObservable = () => setOpenCreateObservable(true);
  const handleCloseCreateObservable = () => setOpenCreateObservable(false);

  return show && (
    <div
      style={{
        width: '100%',
        display: 'flex',
        justifyContent: 'end',
      }}
    >
      {showSDOs && (
        <StixDomainObjectCreation
          display={true}
          inputValue={searchPaginationOptions?.search}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          speeddial={false}
          open={undefined}
          handleClose={undefined}
          onCompleted={undefined}
          creationCallback={undefined}
          confidence={undefined}
          defaultCreatedBy={undefined}
          isFromBulkRelation={undefined}
          defaultMarkingDefinitions={undefined}
          stixDomainObjectTypes={actualTypeFilterValues}
          controlledDialStyles={{ marginRight: '10px' }}
        />
      )}
      {showSCOs && (
        <Button
          onClick={handleOpenCreateObservable}
          variant='contained'
          style={{ marginRight: '10px' }}
        >
          {t_i18n('Create an observable')}
        </Button>
      )}
      <StixCyberObservableCreation
        display={true}
        contextual={true}
        inputValue={searchPaginationOptions?.search}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        speeddial={true}
        open={openCreateObservable}
        handleClose={handleCloseCreateObservable}
        type={undefined}
        defaultCreatedBy={undefined}
      />
    </div>
  );
};

export default StixCoreRelationshipCreationHeaderButtons;
