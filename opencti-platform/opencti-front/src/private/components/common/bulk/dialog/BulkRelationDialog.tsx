import React, { FunctionComponent, useState, ChangeEvent, useEffect } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import BulkSelectRawLineData from '@components/common/bulk/BulkSelectRawLineData';
import EntityRelationshipCard from '@components/common/bulk/EntityRelationshipCard';
import { stixCoreRelationshipCreationFromEntityFromMutation, TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import { commitMutation, fetchQuery, MESSAGING$ } from 'src/relay/environment';
import Typography from '@mui/material/Typography';
import { useFormatter } from 'src/components/i18n';
import useAuth from 'src/utils/hooks/useAuth';
import { ArrowRightAlt } from '@mui/icons-material';
import MenuItem from '@mui/material/MenuItem';
import { Select, SelectChangeEvent } from '@mui/material';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import { StixCoreRelationshipAddInput } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationMutation.graphql';
import { RelayError } from 'src/relay/relayTypes';
import Loader from 'src/components/Loader';
import { graphql } from 'react-relay';
import { ForceUpdateEvent } from '@components/common/bulk/useForceUpdate';
import BulkTextModalButton from 'src/components/fields/BulkTextField/BulkTextModalButton';
import StixDomainObjectCreation from '@components/common/stix_domain_objects/StixDomainObjectCreation';
import { PaginationOptions } from 'src/components/list_lines';
import StixCyberObservableCreation from '@components/observations/stix_cyber_observables/StixCyberObservableCreation';
import { allEntitiesKeyList, type StixCoreResultsType } from '../utils/querySearchEntityByText';
import { getRelationsFromOneEntityToAny, RelationsDataFromEntity, RelationsToEntity } from '../../../../../utils/Relation';

export const searchStixCoreObjectsByRepresentativeQuery = graphql`
  query BulkRelationDialogQuery(
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    stixCoreObjects(types: $types, search: $search, filters: $filters) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          objectLabel {
            id
            value
            color
          }
          creators {
            id
            name
          }
          containersNumber {
            total
          }
        }
      }
    }
  }
`;

interface BulkRelationDialogProps {
  stixDomainObjectId: string;
  stixDomainObjectName: string;
  stixDomainObjectType: string;
  isOpen: boolean;
  onClose: () => void;
  selectedEntities: TargetEntity[];
  defaultRelationshipType?: string;
  paginationKey: string;
  paginationOptions: PaginationOptions;
}

export interface BulkEntityTypeInfo {
  representative: string;
  searchTerm: string;
  entityName?: string;
  entityType?: string;
  index: number;
  isMatchingEntity: boolean;
  isExisting: boolean;
  selectedEntityType: RelationsToEntity;
  entityTypeList?: entityTypeListType[];
}

type entityTypeListType = {
  entity_type: string;
  representative: string;
  id: string;
};

type missingEntityType = {
  key: string;
  values: string[];
};

const classes = {
  dialog: {
    '.MuiDialog-paper': {
      overflowY: 'unset',
      height: '60vh',
    },
  },
  dialogContent: {
    '.MuiDialogContent-root': {
      paddingTop: '20px',
      overflow: 'initial',
    },
  },
};

const querySearchEntityByText = async (text: string) => {
  const searchPaginationOptions = {
    filters: {
      mode: 'and',
      filters: [
        {
          key: allEntitiesKeyList,
          values: [text],
        },
      ],
      filterGroups: [],
    },
    count: 1,
  };

  const result = await fetchQuery(
    searchStixCoreObjectsByRepresentativeQuery,
    searchPaginationOptions,
  ).toPromise()
    .then((data) => {
      return data;
    }) as StixCoreResultsType;
  return { ...result, searchTerm: text };
};

export const toHeaderWidth = 180;
export const entityTypeHeaderWidth = 180;
export const entityNameHeaderWidth = 180;
export const matchHeaderWidth = 180;

const EntityTypeWithoutBulkEntityCreation = [
  'Attack-Pattern',
  'Course-of-Action',
  'Feedback',
  'Grouping',
  'Incident',
  'Malware-Analysis',
  'Note',
  'Report',
  'Opinion',
  'Position',
];

const BulkRelationDialog : FunctionComponent<BulkRelationDialogProps> = ({
  stixDomainObjectId,
  stixDomainObjectType,
  stixDomainObjectName,
  isOpen,
  onClose,
  selectedEntities,
  defaultRelationshipType,
  paginationKey,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [textAreaValue, setTextAreaValue] = useState<string[]>([...selectedEntities.map((item) => item.name ?? '')]);
  const [entityToSearch, setEntityToSearch] = useState<string[]>([]);
  const [bulkEntityList, setBulkEntityList] = useState<BulkEntityTypeInfo[]>([]);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [isObjectCreationFormOpen, setIsObjectCreationFormOpen] = useState<boolean>(false);
  const [missingEntity, setMissingEntity] = useState<missingEntityType>();
  const [isFirstLoadDone, setIsFirstLoadDone] = useState<boolean>(false);

  useEffect(() => {
    const timeoutId = setTimeout(() => {
      const newEntityToSearch = [...textAreaValue];
      if (newEntityToSearch.length && newEntityToSearch[newEntityToSearch.length - 1] === '') newEntityToSearch.pop();
      setEntityToSearch([...newEntityToSearch]);
    }, 500);
    return () => clearTimeout(timeoutId);
  }, [textAreaValue, 500]);

  const { schema } = useAuth();
  const scoLabelList = schema.scos.map(({ label }) => label);
  const resolvedRelations: RelationsDataFromEntity = getRelationsFromOneEntityToAny(stixDomainObjectType, schema);
  const entityList = resolvedRelations.allRelationsToEntity;
  const relationListArray = resolvedRelations.allPossibleRelations;

  const getDefaultSelectedRelationshipType = () => {
    if (defaultRelationshipType && relationListArray.includes(defaultRelationshipType.toLowerCase())) {
      return defaultRelationshipType.toLowerCase();
    }
    return relationListArray[0];
  };

  const [selectedRelationType, setSelectedRelationType] = useState<string>(getDefaultSelectedRelationshipType());

  const getRelationMatchStatus = (selectedEntityType: RelationsToEntity, entityTypeList: entityTypeListType[]): boolean => {
    const matchingEntity = entityTypeList?.find((foundEntity) => foundEntity.entity_type === selectedEntityType?.toEntitytype);
    return !!(selectedEntityType?.legitRelations.includes(selectedRelationType) && matchingEntity);
  };

  const selectMissingEntites = (currentBulkEntityList: BulkEntityTypeInfo[]) => {
    const foundMissingEntity = currentBulkEntityList.find((item) => !item.isMatchingEntity);
    if (!foundMissingEntity) return;
    if (EntityTypeWithoutBulkEntityCreation.includes(foundMissingEntity.selectedEntityType.toEntitytype)) {
      setMissingEntity({
        key: foundMissingEntity.selectedEntityType.toEntitytype,
        values: [foundMissingEntity.searchTerm],
      });
    } else {
      const { selectedEntityType: { toEntitytype } } = foundMissingEntity;
      setMissingEntity({
        key: toEntitytype,
        values: currentBulkEntityList
          .filter((item) => item.selectedEntityType.toEntitytype === toEntitytype)
          .map((item) => item.searchTerm),
      });
    }
  };

  useEffect(() => {
    selectMissingEntites(bulkEntityList);
  }, [bulkEntityList]);

  useEffect(() => {
    const getBulkEntities = async () => {
      if (missingEntity) setMissingEntity(undefined);
      const rawLinesPromises: Promise<StixCoreResultsType>[] = entityToSearch.map((content) => querySearchEntityByText(content));
      const resultsAwait: StixCoreResultsType[] = await Promise.all(rawLinesPromises);
      const newBulkEntityList = resultsAwait.reduce((acc: BulkEntityTypeInfo[], cur: StixCoreResultsType, index: number) => {
        const foundItem = bulkEntityList.find((item) => item.searchTerm === cur.searchTerm);
        if (cur.stixCoreObjects.edges.length > 0) {
          const { edges } = cur.stixCoreObjects;
          const stixObject = edges[0].node;
          const entityTypeList = edges.map(({ node }) => ({
            entity_type: node.entity_type,
            representative: node.representative.main,
            id: node.id,
          }));
          const foundEntityType = entityList.filter((entityType) => entityType.toEntitytype === entityTypeList[0].entity_type);
          const newSelectedEntityType: RelationsToEntity = foundEntityType.length ? foundEntityType[0] : entityList[0];
          let selectedEntityType = foundItem?.selectedEntityType ?? newSelectedEntityType;
          const isMatchingEntity = getRelationMatchStatus(newSelectedEntityType, entityTypeList);
          const foundSelectedItem = selectedEntities.find((item) => item.name === cur.searchTerm);
          if (!isFirstLoadDone) {
            const selectedEntityTypeFromSelectedEntity = entityList.find((item) => item.toEntitytype === foundSelectedItem?.entity_type);
            if (selectedEntityTypeFromSelectedEntity) selectedEntityType = selectedEntityTypeFromSelectedEntity;
            setIsFirstLoadDone(true);
          }
          return [...acc, {
            representative: foundItem?.representative ?? stixObject.representative.main,
            entityTypeList,
            isMatchingEntity,
            isExisting: true,
            selectedEntityType,
            index,
            searchTerm: cur.searchTerm,
          }];
        }
        return [...acc, {
          isExisting: false,
          representative: foundItem?.representative ?? cur.searchTerm,
          selectedEntityType: foundItem?.selectedEntityType ?? entityList[0],
          index,
          isMatchingEntity: false,
          searchTerm: cur.searchTerm,
        }];
      }, []);
      setBulkEntityList([...newBulkEntityList]);
    };
    getBulkEntities().catch(() => false);
  }, [entityToSearch]);

  useEffect(() => {
    const bulkEntityListToEdit = bulkEntityList.map((item) => {
      const { selectedEntityType, entityTypeList } = item;
      return {
        ...item,
        isMatchingEntity: getRelationMatchStatus(selectedEntityType, entityTypeList ?? []),
      };
    });
    setBulkEntityList([...bulkEntityListToEdit]);
  }, [selectedRelationType]);
  const handleChangeSelectedRelationType = (event: SelectChangeEvent) => {
    setSelectedRelationType(event.target.value);
  };

  const handleChangeTextArea = async (event: ChangeEvent<HTMLTextAreaElement>) => {
    const rawLines: string[] = event.target.value.split(/\r?\n/);
    if (rawLines.length === 1 && rawLines[0] === '') {
      setTextAreaValue([]);
      return;
    }
    setTextAreaValue([...rawLines]);
  };

  const onDeleteEntity = (entityIndex: number) => {
    const filteredBulkEntityList = bulkEntityList.filter((_, index) => index !== entityIndex);
    const filteredTextAreaValue = textAreaValue.filter((_, index) => index !== entityIndex);
    setBulkEntityList([...filteredBulkEntityList]);
    setTextAreaValue([...filteredTextAreaValue]);
  };

  const onChangeEntityType = (value: RelationsToEntity, entityIndex: number) => {
    const bulkEntityListToEdit = bulkEntityList;
    const { entityTypeList } = bulkEntityListToEdit[entityIndex];
    const foundEntityType = (entityTypeList ?? []).find((item) => item.entity_type === value.toEntitytype);
    if (foundEntityType) bulkEntityListToEdit[entityIndex].representative = foundEntityType.representative;
    bulkEntityListToEdit[entityIndex].selectedEntityType = value;
    bulkEntityListToEdit[entityIndex].isMatchingEntity = getRelationMatchStatus(value, entityTypeList ?? []);
    setBulkEntityList([...bulkEntityListToEdit]);
    selectMissingEntites(bulkEntityList);
  };

  const handleOpenObjectCreateEntityForm = () => setIsObjectCreationFormOpen(true);

  const handleRefreshBulkEntityList = () => {
    setEntityToSearch([...entityToSearch]);
  };

  const handleCloseObjectCreateEntityForm = () => setIsObjectCreationFormOpen(false);

  const onCompletedObjectCreation = () => {
    handleRefreshBulkEntityList();
    handleCloseObjectCreateEntityForm();
  };

  const commit = (finalValues: StixCoreRelationshipAddInput) => {
    return new Promise((resolve, reject) => {
      commitMutation({
        mutation: stixCoreRelationshipCreationFromEntityFromMutation,
        variables: { input: finalValues },
        optimisticUpdater: undefined,
        setSubmitting: undefined,
        optimisticResponse: undefined,
        updater: undefined,
        onError: (error: Error) => {
          reject(error);
        },
        onCompleted: (response: Response) => {
          resolve(response);
        },
      });
    });
  };

  const handleSubmit = async () => {
    setIsSubmitting(true);
    for (const bulkEntity of bulkEntityList) {
      const foundEntityType = bulkEntity.entityTypeList?.find(({ entity_type }) => entity_type === bulkEntity.selectedEntityType.toEntitytype);
      if (!foundEntityType) return;
      const finalValues = {
        relationship_type: selectedRelationType,
        fromId: stixDomainObjectId,
        toId: foundEntityType.id,
      };
      try {
        // eslint-disable-next-line no-await-in-loop
        await commit(finalValues);
      } catch (error) {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
        setIsSubmitting(false);
      }
    }
    setIsSubmitting(false);
    onClose();
    dispatchEvent(new CustomEvent(ForceUpdateEvent));
  };
  const getTextAreaValue = () => textAreaValue.join('\n');
  const isSubmitDisable = !bulkEntityList.every((item) => item.isMatchingEntity) || bulkEntityList.length === 0;

  const renderHeaders = () => (
    <Box sx={{ height: '30px', display: 'flex', gap: '15px' }}>
      <Typography sx={{ width: `${toHeaderWidth}px` }}>{t_i18n('relationship_to')}</Typography>
      <Typography sx={{ width: `${entityTypeHeaderWidth}px` }}>{t_i18n('entity_type')}</Typography>
      <Typography sx={{ width: `${entityNameHeaderWidth}px` }}>{t_i18n('Representation')}</Typography>
      <Typography sx={{ width: `${matchHeaderWidth}px` }}>{t_i18n('Match')}</Typography>
      <Box sx={{ width: '50px' }} />
    </Box>
  );

  const renderLoader = () => (
    <Box sx={{ width: '100%', height: '100%', backgroundColor: 'black', opacity: 0.5, position: 'absolute' }}>
      <Loader />
    </Box>
  );

  const renderStixDomainObjectCreationForm = () => {
    if (!isObjectCreationFormOpen || !missingEntity) return null;

    if (scoLabelList.includes(missingEntity.key)) {
      return (
        <StixCyberObservableCreation
          paginationOptions={paginationOptions}
          open={isObjectCreationFormOpen}
          speeddial={isObjectCreationFormOpen}
          inputValue={missingEntity.values?.join('\n') ?? ''}
          display={isObjectCreationFormOpen}
          paginationKey={paginationKey}
          handleClose={handleCloseObjectCreateEntityForm}
          type={missingEntity.key}
          contextual
        />
      );
    }
    return (
      <StixDomainObjectCreation
        paginationOptions={paginationOptions}
        onCompleted={onCompletedObjectCreation}
        open={isObjectCreationFormOpen}
        speeddial={isObjectCreationFormOpen}
        inputValue={missingEntity.values?.join('\n') ?? ''}
        display={isObjectCreationFormOpen}
        paginationKey={paginationKey}
        stixDomainObjectTypes={missingEntity.key}
        handleClose={handleCloseObjectCreateEntityForm}
        confidence={undefined}
        defaultCreatedBy={undefined}
        defaultMarkingDefinitions={undefined}
      />
    );
  };

  return (
    <>
      <Dialog open={isOpen} PaperProps={{ elevation: 1 }} scroll='paper' sx={{ overflowY: 'hidden', ...classes.dialog, ...classes.dialogContent }} onClose={onClose} maxWidth="xl">
        {isSubmitting && renderLoader()}
        <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>{t_i18n(`Create relationships in bulk for ${stixDomainObjectType}`)}</div>
          {missingEntity ? <BulkTextModalButton title={t_i18n('Create missing entities')} onClick={handleOpenObjectCreateEntityForm} /> : null}
        </DialogTitle>
        <DialogContent id="container" sx={{ display: 'flex', overflow: 'hidden', height: '40vh', paddingTop: '20px' }}>
          <Box sx={{ display: 'flex', flexDirection: 'column' }}>
            <Typography sx={{ height: '25px', paddingLeft: '10px' }}>{t_i18n('relationship_from')}</Typography>
            <Box sx={{ display: 'flex' }}>
              <Box id='entityCard' sx={{ display: 'flex', justifyContent: 'center', padding: '0 10px', flexDirection: 'column' }}>
                <EntityRelationshipCard
                  entityName={stixDomainObjectName}
                  entityType={stixDomainObjectType}
                />
              </Box>
              <Box id="relationArrow" sx={{ display: 'flex', justifyContent: 'center', padding: '0 20px', flexDirection: 'column', minWidth: '200px' }}>
                <Select disabled={isSubmitting} onChange={handleChangeSelectedRelationType} value={selectedRelationType}>
                  {relationListArray.map((relation) => (
                    <MenuItem key={relation} value={relation}>
                      {t_i18n(`relationship_${relation}`)}
                    </MenuItem>
                  ))}
                </Select>
                <ArrowRightAlt sx={{ alignSelf: 'center', margin: '10px' }} fontSize="large" />
              </Box>
            </Box>
          </Box>
          <Box>
            {renderHeaders()}
            <Box id="forms" sx={{ display: 'flex', height: '100%', overflowY: 'auto', width: '100%', gap: '10px' }} >
              <Box sx={{ width: `${toHeaderWidth}px` }}>
                <TextField
                  disabled={isSubmitting}
                  inputProps={{ style: { lineHeight: '37px' } }}
                  sx={{
                    '.MuiInputBase-root': {
                      paddingTop: '2px',
                    },
                  }}
                  value={getTextAreaValue()}
                  onChange={handleChangeTextArea}
                  multiline
                  minRows={10}
                  placeholder={'Type or copy paste data in this area.'}
                  variant="outlined"
                />
              </Box>
              <Box style={{ marginTop: '6px' }}>
                {bulkEntityList.map((entity: BulkEntityTypeInfo, index) => {
                  return (
                    <BulkSelectRawLineData
                      entity={entity}
                      key={`${entity.representative}-${index}`}
                      entityIndex={index}
                      selectedRelationType={selectedRelationType}
                      onChangeEntityType={onChangeEntityType}
                      onDeleteEntity={onDeleteEntity}
                      entityList={entityList}
                      isSubmitting={isSubmitting}
                    />
                  );
                })}
              </Box>
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>{t_i18n('Cancel')}</Button>
          <Button onClick={handleSubmit} disabled={isSubmitDisable || isSubmitting} color="secondary">
            {t_i18n('Create')}
          </Button>
        </DialogActions>
      </Dialog>
      {renderStixDomainObjectCreationForm()}
    </>
  );
};

export default BulkRelationDialog;
