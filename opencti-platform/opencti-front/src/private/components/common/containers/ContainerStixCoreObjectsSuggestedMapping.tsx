import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import {
  ContainerStixCoreObjectsSuggestedMappingLine,
  ContainerStixCoreObjectsSuggestedMappingLineDummy,
} from '@components/common/containers/ContainerStixCoreObjectsSuggestedMappingLine';
import { ContainerStixCoreObjectsSuggestedMappingQuery$data } from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import { CheckCircleOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import { ContainerContent_container$data } from '@components/common/containers/__generated__/ContainerContent_container.graphql';
import { InformationOutline } from 'mdi-material-ui';
import DialogTitle from '@mui/material/DialogTitle';
import ListLines from '../../../../components/list_lines/ListLines';
import useAuth from '../../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';

// containers fetching is not good performance wise, we could find a better way to do it by moving it to backend if needed
export const containerStixCoreObjectsSuggestedMappingQuery = graphql`
  query ContainerStixCoreObjectsSuggestedMappingQuery(
    $id: ID!
    $contentSource: String!
    $contentType: AnalysisContentType!
  ) {
    stixCoreObjectAnalysis(id: $id, contentSource: $contentSource, contentType: $contentType) {
      ... on MappingAnalysis {
        analysisType
        analysisStatus
        analysisDate
        mappedEntities {
          matchedString
          isEntityInContainer
          ...ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity
          matchedEntity{
            id
            standard_id
          }
        }
      }
    }
    connectorsForAnalysis {
      id
    }
  }
`;

interface ContainerStixCoreObjectsSuggestedMappingProps {
  container: ContainerContent_container$data;
  suggestedMapping: ContainerStixCoreObjectsSuggestedMappingQuery$data
  suggestedMappingCount: Record<string, number>;
  height: number;
  handleAskNewSuggestedMapping: () => void;
  askingSuggestion: boolean;
  handleValidateSuggestedMapping: (mappingToAdd: { matchedString: string, matchedEntityId: string }[]) => void;
}

type MappedEntityType = NonNullable<NonNullable<ContainerStixCoreObjectsSuggestedMappingQuery$data['stixCoreObjectAnalysis']>['mappedEntities']>[number];

const ContainerStixCoreObjectsSuggestedMapping: FunctionComponent<
ContainerStixCoreObjectsSuggestedMappingProps
> = ({
  container,
  suggestedMapping,
  suggestedMappingCount,
  height,
  handleAskNewSuggestedMapping,
  askingSuggestion,
  handleValidateSuggestedMapping,
}) => {
  const [removedEntities, setRemovedEntities] = useState<string[]>([]);
  const [onlyNotContainedEntities, setOnlyNotContainedEntities] = useState(true);
  const [openValidate, setOpenValidate] = useState(false);
  const [validating, setValidating] = useState(false);
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  // The container ref is not defined on first render, causing infinite scroll issue in the ListLinesContent
  // we force re-render when the ref is ready
  const ref = useRef(null);
  const [, forceUpdate] = React.useReducer((o) => !o, true);
  useEffect(() => {
    forceUpdate();
  }, [ref?.current, askingSuggestion]);

  const LOCAL_STORAGE_KEY = `container-${container.id}-stixCoreObjectsSuggestedMapping`;
  const {
    viewStorage,
    helpers,
  } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      id: container.id,
      types: ['Stix-Core-Object'],
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
      openExports: false,
      view: 'suggestedMapping',
    },
    true,
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;
  const {
    handleSetNumberOfElements,
  } = helpers;

  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '20%',
      isSortable: true,
    },
    createdBy: {
      label: 'Author',
      width: '15%',
      isSortable: isRuntimeSort,
    },
    value: {
      label: 'Value',
      width: '27%',
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      width: '15%',
      isSortable: isRuntimeSort,
    },
    matched_text: {
      label: 'Matched text',
      width: '15%',
      isSortable: true,
    },
    mapping: {
      label: 'Mapping',
      width: '8%',
      isSortable: false,
    },
  };

  const hasConnectorsAvailable = suggestedMapping?.connectorsForAnalysis?.length && suggestedMapping?.connectorsForAnalysis?.length > 0;

  const mappedEntities = (suggestedMapping?.stixCoreObjectAnalysis?.mappedEntities ?? []);
  // Filter entities not removed and only entities not in container if toggle activated
  const filterMappedEntities = (mappedEntity: MappedEntityType) => {
    return !removedEntities.find((r) => r === mappedEntity.matchedEntity?.id)
        && (!onlyNotContainedEntities
            || !mappedEntity.isEntityInContainer);
  };
  const filteredMappedEntities = mappedEntities.filter((e) => filterMappedEntities(e));
  const mappedEntitiesWithNode = filteredMappedEntities.map((e) => { return { node: e }; });

  handleSetNumberOfElements({
    number: filteredMappedEntities.length,
    symbol: '',
    original: filteredMappedEntities.length,
  });

  const handleRemoveSuggestedMappingLine = (matchedId: string) => {
    setRemovedEntities([...removedEntities, matchedId]);
  };

  const handleAskValidateSuggestedMapping = () => {
    setOpenValidate(true);
  };

  const handleValidate = () => {
    setValidating(true);
    const mappingToAdd = filteredMappedEntities.map((e) => {
      return {
        matchedString: e.matchedString,
        matchedEntityId: e.matchedEntity.standard_id,
      };
    });
    handleValidateSuggestedMapping(mappingToAdd);
  };

  const suggestDisabled = !hasConnectorsAvailable || askingSuggestion;

  return (
    <div>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '4px' }}>
        <Box sx={{ flex: 1 }}>
          <FormGroup>
            <FormControlLabel
              control={
                <Switch
                  checked={onlyNotContainedEntities}
                  onChange={() => { setOnlyNotContainedEntities(!onlyNotContainedEntities); }}
                />
                }
              label={t_i18n('Hide entities in container')}
            />
          </FormGroup>
        </Box>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          {!hasConnectorsAvailable && (
          <Tooltip
            title={t_i18n('An analysis connector needs to be available to ask for a mapping suggestion.')}
          >
            <InformationOutline fontSize="small" color="primary" />
          </Tooltip>
          )}
          {askingSuggestion && (
          <Tooltip
            title={t_i18n('An analysis is ongoing, waiting for results.')}
          >
            <InformationOutline fontSize="small" color="primary" />
          </Tooltip>
          )}
          <Tooltip title={t_i18n('Suggest new mapping')}>
            <Button
              variant="contained"
              size="small"
              onClick={handleAskNewSuggestedMapping}
              disabled={suggestDisabled}
            >
              {t_i18n('Suggest new mapping')}
            </Button>
          </Tooltip>
          <Tooltip title={t_i18n('Validate suggested mapping')}>
            <Button
              variant="contained"
              color="secondary"
              onClick={handleAskValidateSuggestedMapping}
              startIcon={<CheckCircleOutlined />}
              size="small"
              disabled={askingSuggestion || filteredMappedEntities.length === 0}
            >
              {t_i18n('Validate')}
            </Button>
          </Tooltip>
        </Box>
      </Box>
      <div style={{ margin: 0, padding: '15px 0 0 0' }} ref={ref} >
        {askingSuggestion
          ? <Loader variant={LoaderVariant.inElement}/>
          : (
            <ListLines
              helpers={helpers}
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={dataColumns}
              iconExtension={false}
              filters={filters}
              availableEntityTypes={['Stix-Core-Object']}
              keyword={searchTerm}
              secondaryAction={true}
              numberOfElements={numberOfElements}
              noPadding={true}
              handleAskNewSuggestedMapping={handleAskNewSuggestedMapping}
              handleValidateSuggestedMapping={handleAskValidateSuggestedMapping}
              mappingCount={filteredMappedEntities.length}
              disabledValidate={filteredMappedEntities.length <= 0}
              enableMappingView
              disableCards
            >
              <ListLinesContent
                initialLoading={false}
                loadMore={() => {}}
                hasMore={() => {}}
                isLoading={() => false}
                dataList={mappedEntitiesWithNode}
                globalCount={mappedEntitiesWithNode.length}
                LineComponent={ContainerStixCoreObjectsSuggestedMappingLine}
                DummyLineComponent={ContainerStixCoreObjectsSuggestedMappingLineDummy}
                dataColumns={dataColumns}
                contentMappingCount={suggestedMappingCount}
                handleRemoveSuggestedMappingLine={handleRemoveSuggestedMappingLine}
                height={height}
                containerRef={ref}
              />
            </ListLines>
          )
        }
      </div>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={openValidate}
        keepMounted
        TransitionComponent={Transition}
        onClose={() => setOpenValidate(false)}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t_i18n('You are about to validate this mapping, it will add suggested entities to your container.')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setOpenValidate(false)}
            disabled={validating}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={handleValidate}
            disabled={validating}
          >
            {t_i18n('Validate')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default ContainerStixCoreObjectsSuggestedMapping;
