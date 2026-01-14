import React, { useState } from 'react';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import { PaginationOptions } from '../../../../components/list_lines';
import { Menu, MenuItem } from '@mui/material';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../../components/Theme';

interface StixCoreRelationshipCreationHeaderButtonsProps {
  showSDOs: boolean;
  showSCOs: boolean;
  actualTypeFilterValues: string[];
  searchPaginationOptions: PaginationOptions;
}

const StixCoreRelationshipCreationHeaderButtons: React.FC<
  StixCoreRelationshipCreationHeaderButtonsProps
> = ({
  showSDOs,
  showSCOs,
  actualTypeFilterValues,
  searchPaginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [openEntityDialog, setOpenEntityDialog] = useState(false);
  const [openObservableDialog, setOpenObservableDialog] = useState(false);

  const menuOpen = Boolean(anchorEl);

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleCreateEntity = () => {
    setOpenEntityDialog(true);
    handleMenuClose();
  };

  const handleCreateObservable = () => {
    setOpenObservableDialog(true);
    handleMenuClose();
  };

  const handleCloseEntityDialog = () => {
    setOpenEntityDialog(false);
  };

  const handleCloseObservableDialog = () => {
    setOpenObservableDialog(false);
  };

  if (!showSDOs && !showSCOs) return null;

  if (showSDOs && !showSCOs) {
    return (
      <StixDomainObjectCreation
        display={true}
        inputValue={searchPaginationOptions.search}
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
      />
    );
  }

  if (!showSDOs && showSCOs) {
    return (
      <>
        <Button onClick={() => setOpenObservableDialog(true)}>
          {t_i18n('Create an observable')}
        </Button>
        <StixCyberObservableCreation
          display={true}
          contextual={true}
          inputValue={searchPaginationOptions.search}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          speeddial={true}
          open={openObservableDialog}
          handleClose={handleCloseObservableDialog}
          type={undefined}
          defaultCreatedBy={undefined}
        />
      </>
    );
  }

  return (
    <>
      <Button
        onClick={handleMenuOpen}
        endIcon={menuOpen ? <ArrowDropUp /> : <ArrowDropDown />}
      >
        {t_i18n('Create')}
      </Button>

      <Menu
        id="create-menu"
        anchorEl={anchorEl}
        open={menuOpen}
        onClose={handleMenuClose}
        sx={{
          '& .MuiPaper-root': {
            backgroundColor: theme.palette.background.secondary,
            backgroundImage: 'none',
          },
        }}
      >
        {showSDOs && (
          <MenuItem onClick={handleCreateEntity}>
            {t_i18n('Entity')}
          </MenuItem>
        )}
        {showSCOs && (
          <MenuItem onClick={handleCreateObservable}>
            {t_i18n('Observable')}
          </MenuItem>
        )}
      </Menu>

      {showSDOs && (
        <StixDomainObjectCreation
          display={false}
          inputValue={searchPaginationOptions.search}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          speeddial={true}
          open={openEntityDialog}
          handleClose={handleCloseEntityDialog}
          onCompleted={undefined}
          creationCallback={undefined}
          confidence={undefined}
          defaultCreatedBy={undefined}
          isFromBulkRelation={undefined}
          defaultMarkingDefinitions={undefined}
          stixDomainObjectTypes={actualTypeFilterValues}
        />
      )}

      {showSCOs && (
        <StixCyberObservableCreation
          display={false}
          contextual={true}
          inputValue={searchPaginationOptions.search}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          speeddial={true}
          open={openObservableDialog}
          handleClose={handleCloseObservableDialog}
          type={undefined}
          defaultCreatedBy={undefined}
        />
      )}
    </>
  );
};

export default StixCoreRelationshipCreationHeaderButtons;
