import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import { BulkEntityTypeInfo, entityNameHeaderWidth, entityTypeHeaderWidth, matchHeaderWidth } from '@components/common/bulk/dialog/BulkRelationDialog';
import { DeleteOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { Autocomplete } from '@mui/material';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import { truncate } from 'src/utils/String';
import { useFormatter } from '../../../../components/i18n';
import { RelationsToEntity } from '../../../../utils/Relation';

interface BulkSelectRawLineDataProps {
  entity: BulkEntityTypeInfo;
  entityIndex: number;
  entityList: RelationsToEntity[];
  isSubmitting: boolean;
  onChangeEntityType: (value: RelationsToEntity, entityIndex: number) => void;
  onDeleteEntity: (entityIndex: number) => void;
  selectedRelationType: string;
}

type autocompleteOptionsType = {
  label: string;
  value: RelationsToEntity;
  groupLabel: string;
  groupOrder: number;
};

const BulkSelectRawLineData: FunctionComponent<BulkSelectRawLineDataProps> = ({
  entity,
  entityIndex,
  entityList,
  selectedRelationType,
  onChangeEntityType,
  onDeleteEntity,
  isSubmitting,
}) => {
  const { t_i18n } = useFormatter();
  const isSearchTermEmpty = entity.searchTerm === '';
  const isMatchingRelationship = entity.selectedEntityType.legitRelations.includes(selectedRelationType);

  const getRelationMatchStatus = () => {
    if (!entity.isExisting && isMatchingRelationship) return t_i18n('Not in platform (compatible)');
    if (entity.isMatchingEntity && isMatchingRelationship) return t_i18n('Found (compatible)');
    return t_i18n('Incompatible');
  };

  const getChipColor = () => {
    if (!entity.isExisting && isMatchingRelationship) return 'error';
    if (entity.isMatchingEntity && isMatchingRelationship) {
      return 'success';
    }
    return 'warning';
  };

  const handleChangeEntityType = (newEntityType: string) => {
    const foundEntityType = entityList.find((entityType) => entityType.toEntitytype === newEntityType);
    if (foundEntityType) onChangeEntityType(foundEntityType, entityIndex);
  };

  const handleDeleteEntity = () => onDeleteEntity(entityIndex);

  const getAutocompleteOptions = () => {
    const possibleEntityTypes = entity.entityTypeList?.map((item) => item.entity_type) ?? [];
    return entityList.reduce((acc: autocompleteOptionsType[], cur) => {
      if (!acc.find((item) => item.label === t_i18n(`entity_${cur.toEntitytype}`))) {
        const isSuggestion = possibleEntityTypes.includes(cur.toEntitytype) && cur.legitRelations.includes(selectedRelationType);
        return [...acc, {
          label: t_i18n(`entity_${cur.toEntitytype}`),
          value: cur,
          groupLabel: isSuggestion ? t_i18n('Suggestions') : t_i18n('Entity list'),
          groupOrder: isSuggestion ? 0 : 1,
        }];
      }
      return [...acc];
    }, [])
      .sort((a, b) => (a.label < b.label ? -1 : 1))
      .sort((a, b) => a.groupOrder - b.groupOrder);
  };

  const getAutocompleteValue = () => {
    const autocompleteOptions = getAutocompleteOptions();
    return autocompleteOptions.find((option) => option.value.toEntitytype === entity.selectedEntityType.toEntitytype);
  };

  return (
    <Box sx={{
      display: 'flex',
      gap: '15px',
      paddingBottom: '5px',
      paddingLeft: '5px',
    }}
    >
      <Box sx={{ minWidth: `${entityTypeHeaderWidth}px` }}>
        <Autocomplete
          autoHighlight
          disableClearable
          disabled={isSearchTermEmpty || isSubmitting}
          noOptionsText={t_i18n('No available options')}
          disablePortal
          options={getAutocompleteOptions()}
          onChange={(event, selectedOption) => {
            handleChangeEntityType(selectedOption.value.toEntitytype);
          }}
          value={getAutocompleteValue()}
          groupBy={(option) => option.groupLabel}
          sx={{ borderBottom: 'none' }}
          renderInput={(params) => (
            <TextField
              sx={{ minWidth: '150px' }}
              {...params}
            />
          )}
        />
      </Box>
      <Box sx={{ minWidth: `${entityNameHeaderWidth}px` }}>
        <Typography
          sx={{
            fontSize: '0.9rem',
            height: '32px',
            margin: 0,
            display: 'flex',
            alignItems: 'center',
          }}
          variant="h3"
        >
          {truncate(isSearchTermEmpty ? entity.searchTerm : entity.representative, 20)}
        </Typography>
      </Box>
      <Box sx={{ minWidth: `${matchHeaderWidth}px` }}>
        <Chip
          style={{ borderRadius: '4px' }}
          label={getRelationMatchStatus()}
          color={getChipColor()}
        />
      </Box>
      <Box>
        <IconButton disabled={isSubmitting} key={`${entity.representative}`} size="small" sx={{ height: '28px', width: '28px' }} onClick={handleDeleteEntity}>
          <DeleteOutlined />
        </IconButton>
      </Box>
    </Box>
  );
};

export default BulkSelectRawLineData;
