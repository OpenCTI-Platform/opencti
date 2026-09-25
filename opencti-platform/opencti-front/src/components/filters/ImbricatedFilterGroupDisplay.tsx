import React, { CSSProperties, FunctionComponent, useState } from 'react';
import { InformationOutline } from 'mdi-material-ui';
import { Chip } from '@filigran/design-system';
import { useFormatter } from '../i18n';
import { FilterRepresentative } from './FiltersModel';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import FilterGroupDialog from './FilterGroupDialog';

interface ImbricatedFilterGroupDisplayProps {
  filterObj: FilterGroup;
  filterMode: string;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  filterStyle?: CSSProperties;
}

const ImbricatedFilterGroupDisplay: FunctionComponent<ImbricatedFilterGroupDisplayProps> = ({
  filterObj,
  filterMode,
  filtersRepresentativesMap,
  filterStyle,
}) => {
  const { filterGroups } = filterObj;
  const [open, setOpen] = useState(false);
  const { t_i18n } = useFormatter();

  const handleClickOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  return (
    <>
      <Chip
        severity="info"
        startIcon={<InformationOutline fontSize="small" />}
        label={t_i18n('Filters are not fully displayed')}
        onClick={handleClickOpen}
        style={filterStyle}
      />
      <FilterGroupDialog
        open={open}
        onClose={handleClose}
        filterGroups={filterGroups}
        filterMode={filterMode}
        jsonObject={filterObj}
        filtersRepresentativesMap={filtersRepresentativesMap}
        title={t_i18n('Imbricated filter groups')}
        description={t_i18n('This filter group contains nested filter groups. The full content is displayed below for reference. It can be edited directly from the filters line on the entity page.')}
      />
    </>
  );
};

export default ImbricatedFilterGroupDisplay;
