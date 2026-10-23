import React, { FunctionComponent, ReactNode, useEffect, useState } from 'react';
import * as R from 'ramda';
import { Form, Formik, FormikConfig } from 'formik';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import IconButton from '@common/button/IconButton';
import { Checkbox, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Add } from '@mui/icons-material';
import type { SxProps, Theme } from '@mui/material';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { GlobeModel, HexagonOutline } from 'mdi-material-ui';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { containerAddStixCoreObjectsLinesRelationAddMutation, containerAddStixCoreObjectsLinesRelationDeleteMutation } from './ContainerAddStixCoreObjectsLines';
import { reportKnowledgeGraphMutationRelationDeleteMutation, reportKnowledgeGraphtMutationRelationAddMutation } from '../../analyses/reports/ReportKnowledgeGraphQuery';
import {
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
} from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables,
} from '../stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data,
} from '../stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data.graphql';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node$data,
} from '../stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node.graphql';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import useAuth from '../../../../utils/hooks/useAuth';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps, DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import Drawer from '../drawer/Drawer';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { LocalStorage } from '../../../../utils/hooks/useLocalStorageModel';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { insertNode } from '../../../../utils/store';
import CommitMessage from '../form/CommitMessage';
import { ExternalReferencesValues } from '../form/ExternalReferencesField';
import { DefaultMarking } from '../../settings/marking_definitions/markingDefinition.types';

export type ContainerAddStixCoreObjectsLine = StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node$data;

// The mapping view gives standard_id instead of id
type ContainerStixCoreObjects = ReadonlyArray<{ readonly node: { readonly id?: string } } | null | undefined>;

type SearchPaginationOptions = StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables;

interface ReferencesFormValues {
  message: string;
  references: ExternalReferencesValues;
}

// Shared by the actions of the speed dial; sx, as the hover cannot be set with an inline style
const speedDialButtonSx: SxProps<Theme> = (theme) => ({
  backgroundColor: theme.palette.primary.main,
  color: theme.palette.primary.contrastText,
  '&:hover': {
    backgroundColor: theme.palette.primary.main,
  },
});

interface ContainerAddStixCoreObjectsSelectEntitiesProps {
  storageKey: string;
  initialValues: LocalStorage;
  dataColumns: DataTableProps['dataColumns'];
  searchPaginationOptions: Omit<SearchPaginationOptions, 'count'>;
  contextFilters: FilterGroup;
  targetTypes: string[];
  createButton: ReactNode;
  containerId: string;
  paginationOptions?: Record<string, unknown>;
  knowledgeGraph?: boolean;
  containerStixCoreObjects?: ContainerStixCoreObjects;
  onAdd?: (stixCoreObject: ContainerAddStixCoreObjectsLine) => void;
  onDelete?: (stixCoreObject: ContainerAddStixCoreObjectsLine) => void;
  enableReferences?: boolean;
}

// Own component so that the entities are only queried once the drawer shows the list
const ContainerAddStixCoreObjectsSelectEntities: FunctionComponent<ContainerAddStixCoreObjectsSelectEntitiesProps> = ({
  storageKey,
  initialValues,
  dataColumns,
  searchPaginationOptions,
  contextFilters,
  targetTypes,
  createButton,
  containerId,
  paginationOptions,
  knowledgeGraph,
  containerStixCoreObjects,
  onAdd,
  onDelete,
  enableReferences,
}) => {
  const [tableRootRef, setTableRootRef] = useState<HTMLDivElement | null>(null);
  const [referenceDialogOpened, setReferenceDialogOpened] = useState(false);
  const [currentlyToggledCoreObject, setCurrentlyToggledCoreObject] = useState<ContainerAddStixCoreObjectsLine | null>(null);
  // Indexed by id, or by standard_id for the mapping view
  const [addedStixCoreObjects, setAddedStixCoreObjects] = useState<Record<string, { id?: string }>>(() => R.indexBy(
    (n) => n.id ?? '',
    (containerStixCoreObjects ?? []).flatMap((n) => (n?.node.id ? [n.node] : [])),
  ));
  const queryRef = useQueryLoading<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery>(
    stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    { ...searchPaginationOptions, count: 25 },
  );

  const isAdded = (stixCoreObject: ContainerAddStixCoreObjectsLine) => stixCoreObject.id in addedStixCoreObjects
    || stixCoreObject.standard_id in addedStixCoreObjects;
  const markAsAdded = (stixCoreObject: ContainerAddStixCoreObjectsLine) => setAddedStixCoreObjects((current) => ({
    ...current,
    [stixCoreObject.id]: stixCoreObject,
  }));
  const markAsRemoved = (stixCoreObject: ContainerAddStixCoreObjectsLine) => setAddedStixCoreObjects((current) => R.omit(
    [stixCoreObject.id, stixCoreObject.standard_id],
    current,
  ));
  // ID is not valid pagination options, will be handled better when hooked
  const { id: _, count: __, ...containerPaginationOptions } = paginationOptions ?? {};

  const sendStixCoreObjectModification = (
    stixCoreObject: ContainerAddStixCoreObjectsLine,
    commitMessage = '',
    references: string[] = [],
    setSubmitting?: (isSubmitting: boolean) => void,
    resetForm?: () => void,
  ) => {
    const complete = (callback?: (o: ContainerAddStixCoreObjectsLine) => void) => {
      if (typeof callback === 'function') {
        callback(stixCoreObject);
      }
      if (setSubmitting) setSubmitting(false);
      if (resetForm) resetForm();
    };
    if (isAdded(stixCoreObject)) {
      commitMutation({
        mutation: knowledgeGraph
          ? reportKnowledgeGraphMutationRelationDeleteMutation
          : containerAddStixCoreObjectsLinesRelationDeleteMutation,
        variables: {
          id: containerId,
          toId: stixCoreObject.id,
          relationship_type: 'object',
          commitMessage,
          references,
        },
        updater: knowledgeGraph ? undefined : (store: RecordSourceSelectorProxy) => {
          markAsRemoved(stixCoreObject);
          const containerRecord = store.get(containerId);
          const conn = containerRecord && ConnectionHandler.getConnection(
            containerRecord,
            'Pagination_objects',
            containerPaginationOptions,
          );
          if (conn) ConnectionHandler.deleteNode(conn, stixCoreObject.id);
        },
        onCompleted: () => {
          markAsRemoved(stixCoreObject);
          complete(onDelete);
        },
        setSubmitting,
      });
    } else {
      const input = {
        toId: stixCoreObject.id,
        relationship_type: 'object',
      };
      commitMutation({
        mutation: knowledgeGraph
          ? reportKnowledgeGraphtMutationRelationAddMutation
          : containerAddStixCoreObjectsLinesRelationAddMutation,
        variables: {
          id: containerId,
          input,
          commitMessage,
          references,
        },
        optimisticUpdater: knowledgeGraph ? undefined : () => markAsAdded(stixCoreObject),
        updater: knowledgeGraph ? undefined : (store: RecordSourceSelectorProxy) => {
          insertNode(
            store,
            'Pagination_objects',
            containerPaginationOptions,
            'containerEdit',
            containerId,
            'relationAdd',
            { input, commitMessage, references },
            'to',
          );
        },
        onCompleted: () => {
          if (knowledgeGraph) markAsAdded(stixCoreObject);
          complete(onAdd);
        },
        setSubmitting,
      });
    }
  };

  const handleToggle = (stixCoreObject: ContainerAddStixCoreObjectsLine) => {
    if (enableReferences) {
      setCurrentlyToggledCoreObject(stixCoreObject);
      setReferenceDialogOpened(true);
    } else {
      sendStixCoreObjectModification(stixCoreObject);
    }
  };
  const closeReferencesPopup = () => {
    setReferenceDialogOpened(false);
    setCurrentlyToggledCoreObject(null);
  };
  const submitReference: FormikConfig<ReferencesFormValues>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    if (!currentlyToggledCoreObject) return;
    const references = (values.references ?? []).map((reference) => reference.value);
    sendStixCoreObjectModification(currentlyToggledCoreObject, values.message, references, setSubmitting, resetForm);
  };

  const preloadedPaginationProps = {
    linesQuery: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    linesFragment: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
    queryRef,
  } as UsePreloadedPaginationFragment<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery>;

  return (
    <div style={{ flex: '1 0 0', overflow: 'hidden' }} ref={setTableRootRef}>
      {queryRef && (
        <DataTable
          disableToolBar
          disableNavigation
          // The checkbox tells whether the entity is in the container, not the line selection
          disableLineSelection
          hideSavedFilters
          variant={DataTableVariant.inline}
          rootRef={tableRootRef ?? undefined}
          dataColumns={dataColumns}
          resolvePath={(data: StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
          storageKey={storageKey}
          lineFragment={stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          entityTypes={targetTypes}
          availableEntityTypes={targetTypes}
          additionalFilterKeys={['entity_type']}
          createButton={createButton}
          icon={(stixCoreObject: ContainerAddStixCoreObjectsLine) => <Checkbox checked={isAdded(stixCoreObject)} />}
          onLineClick={handleToggle}
        />
      )}
      {enableReferences && (
        <Formik<ReferencesFormValues>
          initialValues={{ message: '', references: [] }}
          onSubmit={submitReference}
        >
          {({ submitForm, isSubmitting, setFieldValue, values }) => (
            <Form>
              <CommitMessage
                handleClose={closeReferencesPopup}
                open={referenceDialogOpened}
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                values={values.references}
                id={containerId}
                noStoreUpdate={true}
              />
            </Form>
          )}
        </Formik>
      )}
    </div>
  );
};

interface ContainerAddStixCoreObjectsProps {
  containerId: string;
  targetStixCoreObjectTypes: string[];
  defaultCreatedBy?: unknown;
  defaultMarkingDefinitions?: readonly DefaultMarking[];
  knowledgeGraph?: boolean;
  containerStixCoreObjects?: ContainerStixCoreObjects;
  confidence?: number | null;
  paginationOptions?: Record<string, unknown>;
  onAdd?: (stixCoreObject: ContainerAddStixCoreObjectsLine) => void;
  onDelete?: (stixCoreObject: ContainerAddStixCoreObjectsLine) => void;
  // Mapping mode: the drawer is opened by the content mapping, to search the selected text
  mapping?: boolean;
  selectedText?: string;
  openDrawer?: boolean;
  handleClose?: () => void;
  enableReferences?: boolean;
}

const ContainerAddStixCoreObjects: FunctionComponent<ContainerAddStixCoreObjectsProps> = ({
  targetStixCoreObjectTypes,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  containerId,
  knowledgeGraph,
  containerStixCoreObjects,
  confidence,
  paginationOptions,
  onAdd,
  onDelete,
  mapping,
  selectedText,
  openDrawer,
  handleClose,
  enableReferences,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [openSpeedDial, setOpenSpeedDial] = useState(false);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);

  const { stixDomainObjectTypes, stixCyberObservableTypes } = useAttributes();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const isTypeDomainObject = (types: string[]) => {
    return types.some((r) => stixDomainObjectTypes.indexOf(r) >= 0)
      || types.includes('Stix-Domain-Object');
  };
  const isTypeObservable = (types: string[]) => {
    return types.some((r) => stixCyberObservableTypes.indexOf(r) >= 0)
      || types.includes('Stix-Cyber-Observable');
  };
  const isOnlyDomainObjects = isTypeDomainObject(targetStixCoreObjectTypes) && !isTypeObservable(targetStixCoreObjectTypes);
  const isOnlyObservables = isTypeObservable(targetStixCoreObjectTypes) && !isTypeDomainObject(targetStixCoreObjectTypes);

  const resolveAvailableTypes = () => {
    if (isOnlyDomainObjects) {
      return 'Stix-Domain-Object';
    }
    if (isOnlyObservables) {
      return 'Stix-Cyber-Observable';
    }
    return 'Stix-Core-Object';
  };

  const LOCAL_STORAGE_KEY = `container-${containerId}-add-${targetStixCoreObjectTypes}`;
  const initialValues = {
    searchTerm: '',
    sortBy: '_score',
    orderAsc: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers } = usePaginationLocalStorage<SearchPaginationOptions>(
    LOCAL_STORAGE_KEY,
    initialValues,
    true,
  );

  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
  } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext(targetStixCoreObjectTypes, filters);

  // In mapping mode, the selected text of the content is searched, until the user types another search
  useEffect(() => {
    if (mapping && selectedText) {
      helpers.handleSearch(selectedText);
    }
  }, [mapping, selectedText]);
  const keyword = searchTerm;
  const handleOpenCreateEntity = () => {
    setOpenCreateEntity(true);
    setOpenSpeedDial(false);
  };
  const handleCloseCreateEntity = () => {
    setOpenCreateEntity(false);
    setOpenSpeedDial(false);
  };
  const handleOpenCreateObservable = () => {
    setOpenCreateObservable(true);
    setOpenSpeedDial(false);
  };
  const handleCloseCreateObservable = () => {
    setOpenCreateObservable(false);
    setOpenSpeedDial(false);
  };
  const renderDomainObjectCreation = (searchPaginationOptions: Omit<SearchPaginationOptions, 'count'>) => {
    return (
      <StixDomainObjectCreation
        display={open}
        inputValue={keyword}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        confidence={confidence}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
        stixDomainObjectTypes={targetStixCoreObjectTypes}
        creationCallback={undefined}
        onCompleted={undefined}
        isFromBulkRelation={undefined}
        open={undefined}
        speeddial={undefined}
        handleClose={undefined}
      />
    );
  };
  const renderObservableCreation = (searchPaginationOptions: Omit<SearchPaginationOptions, 'count'>) => {
    return (
      <StixCyberObservableCreation
        display={open}
        contextual={true}
        type={undefined}
        inputValue={keyword}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions as unknown as []}
      />
    );
  };
  const renderStixCoreObjectCreation = (searchPaginationOptions: Omit<SearchPaginationOptions, 'count'>) => {
    return (
      <>
        <SpeedDial
          style={{
            position: 'fixed',
            bottom: 30,
            right: 30,
            zIndex: 1100,
          }}
          ariaLabel="Create"
          icon={<SpeedDialIcon />}
          onClose={() => setOpenSpeedDial(false)}
          onOpen={() => setOpenSpeedDial(true)}
          open={openSpeedDial}
          FabProps={{
            color: 'secondary',
          }}
        >
          <SpeedDialAction
            title={t_i18n('Create an observable')}
            icon={<HexagonOutline />}
            tooltipTitle={t_i18n('Create an observable')}
            onClick={() => handleOpenCreateObservable()}
            FabProps={{
              sx: speedDialButtonSx,
            }}
          />
          <SpeedDialAction
            title={t_i18n('Create an entity')}
            icon={<GlobeModel />}
            tooltipTitle={t_i18n('Create an entity')}
            onClick={() => handleOpenCreateEntity()}
            FabProps={{
              sx: speedDialButtonSx,
            }}
          />
        </SpeedDial>
        <StixDomainObjectCreation
          display={open}
          inputValue={keyword}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          confidence={confidence}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions}
          stixDomainObjectTypes={undefined}
          speeddial={true}
          open={openCreateEntity}
          handleClose={() => handleCloseCreateEntity()}
          creationCallback={undefined}
          onCompleted={undefined}
          isFromBulkRelation={undefined}
        />
        <StixCyberObservableCreation
          display={open}
          contextual={true}
          type={undefined}
          inputValue={keyword}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions as unknown as []}
          speeddial={true}
          open={openCreateObservable}
          handleClose={() => handleCloseCreateObservable()}
        />
      </>
    );
  };
  const renderEntityCreation = (searchPaginationOptions: Omit<SearchPaginationOptions, 'count'>) => {
    if (isOnlyDomainObjects) {
      return renderDomainObjectCreation(searchPaginationOptions);
    }
    if (isOnlyObservables) {
      return renderObservableCreation(searchPaginationOptions);
    }
    return renderStixCoreObjectCreation(searchPaginationOptions);
  };
  const buildColumns = () => {
    return {
      entity_type: {
        label: 'Type',
        percentWidth: 15,
        isSortable: true,
      },
      value: {
        label: 'Value',
        percentWidth: 33,
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        percentWidth: 15,
        isSortable: isRuntimeFieldEnable(),
      },
      objectLabel: {
        label: 'Labels',
        percentWidth: 22,
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        percentWidth: 15,
        isSortable: isRuntimeFieldEnable(),
      },
    };
  };
  const renderSearchResults = (searchPaginationOptions: Omit<SearchPaginationOptions, 'count'>) => {
    return (
      <ContainerAddStixCoreObjectsSelectEntities
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        dataColumns={buildColumns()}
        searchPaginationOptions={searchPaginationOptions}
        contextFilters={contextFilters}
        targetTypes={targetStixCoreObjectTypes}
        createButton={renderEntityCreation(searchPaginationOptions)}
        containerId={containerId}
        paginationOptions={paginationOptions}
        knowledgeGraph={knowledgeGraph}
        containerStixCoreObjects={containerStixCoreObjects}
        onAdd={onAdd}
        onDelete={onDelete}
        enableReferences={enableReferences}
      />
    );
  };

  // Also the pagination options of the creations, so that a created entity is inserted in the list
  const searchPaginationOptions = {
    types: [resolveAvailableTypes()],
    search: keyword,
    filters: contextFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  } as unknown as Omit<SearchPaginationOptions, 'count'>;
  const renderButton = () => {
    if (knowledgeGraph) {
      return (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>
              <IconButton
                onClick={() => setOpen(true)}
                variant="tertiary"
                size="small"
                aria-label={t_i18n('Add an entity to this container')}
              >
                <Add />
              </IconButton>
            </span>
          </TooltipTrigger>
          <TooltipContent>{t_i18n('Add an entity to this container')}</TooltipContent>
        </Tooltip>
      );
    }
    return (
      <IconButton
        aria-label="Add"
        onClick={() => setOpen(true)}
        variant="tertiary"
        size="small"
      >
        <Add fontSize="small" />
      </IconButton>
    );
  };
  return (
    <>
      {!mapping && renderButton()}
      <Drawer
        open={mapping ? openDrawer : open}
        onClose={() => {
          if (mapping) {
            handleClose?.();
          } else {
            setOpen(false);
          }
        }}
        title={t_i18n('Add entities')}
      >
        <>
          {renderSearchResults(searchPaginationOptions)}
        </>
      </Drawer>
    </>
  );
};

export default ContainerAddStixCoreObjects;
