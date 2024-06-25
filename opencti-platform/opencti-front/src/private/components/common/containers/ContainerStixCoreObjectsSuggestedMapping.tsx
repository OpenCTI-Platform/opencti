import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { ContainerContent_container$data } from '@components/common/containers/__generated__/ContainerContent_container.graphql';
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
        mappedEntities {
          matchedString
          ...ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity
          matchedEntity{
            id
            standard_id
            containers{
              edges{
                node{
                  id
                }
              }
            }
          }
        }
      }
    }
  }
`;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '15px 0 0 0',
  },
  button: {
    marginLeft: 2,
  },
}));

interface ContainerStixCoreObjectsSuggestedMappingProps {
  container: ContainerContent_container$data;
  suggestedMapping: ContainerStixCoreObjectsSuggestedMappingQuery$data
  suggestedMappingCount: Record<string, number>;
  height: number;
  handleAskNewSuggestedMapping: () => void;
  handleValidateSuggestedMapping: (mappingToAdd: any) => void;
  isLoading: boolean;
}

const ContainerStixCoreObjectsSuggestedMapping: FunctionComponent<
ContainerStixCoreObjectsSuggestedMappingProps
> = ({ container,
  suggestedMapping,
  suggestedMappingCount,
  height,
  handleSwitchView,
  handleAskNewSuggestedMapping,
  handleValidateSuggestedMapping,
  isLoading,
}) => {
  const [removedEntities, setRemovedEntities] = useState<string[]>([]);
  const [onlyNotContainedEntities, setOnlyNotContainedEntities] = useState(true);
  const [openValidate, setOpenValidate] = useState(false);
  const [validating, setValidating] = useState(false);
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

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
    matched_text: {
      label: 'Matched text',
      width: '17%',
      isSortable: true,
    },
    createdBy: {
      label: 'Author',
      width: '15%',
      isSortable: isRuntimeSort,
    },
    value: {
      label: 'Value',
      width: '30%',
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      width: '10%',
      isSortable: isRuntimeSort,
    },
    mapping: {
      label: 'Mapping',
      width: '8%',
      isSortable: false,
    },
  };

  const mappedEntities = (suggestedMapping?.stixCoreObjectAnalysis?.mappedEntities ?? []);
  const mappedEntitiesWithNode = mappedEntities.map((e) => { return { node: e }; });

  // Filter entities not removed and only entities not in container if toggle activated
  const filterMappedEntities = (mappedEntity) => {
    return !removedEntities.find((r) => r === mappedEntity.node?.matchedEntity?.id)
         && (!onlyNotContainedEntities || !mappedEntity.node?.matchedEntity?.containers?.edges?.find((c: { node: { id: string; }; }) => c.node?.id === container.id));
  };

  const filteredMappedEntities = mappedEntitiesWithNode.filter((e) => filterMappedEntities(e));

  handleSetNumberOfElements({
    number: filteredMappedEntities.length.toString(),
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
    const mappingToAdd = filteredMappedEntities.map((e) => { return { matchedString: e?.node?.matchedString, matchedEntityId: e?.node?.matchedEntity?.standard_id }; });
    handleValidateSuggestedMapping(mappingToAdd);
  };

  if (isLoading) return <Loader variant={LoaderVariant.inElement}/>;

  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  return (
    <div className={classes.container}>
      <FormGroup>
        <FormControlLabel
          control={
            <Switch
              disabled={mappedEntities.length <= 0}
              checked={onlyNotContainedEntities}
              onChange={() => { setOnlyNotContainedEntities(!onlyNotContainedEntities); }}
            />
            }
          label={t_i18n('Entities not in container')}
        />
      </FormGroup>
      <Tooltip title={t_i18n('Suggest new mapping')}>
        <Button
          variant="contained"
          classes={{ root: classes.button }}
          onClick={handleAskNewSuggestedMapping}
        >
          {t_i18n('Suggest new mapping')}
        </Button>
      </Tooltip>
      <Tooltip title={t_i18n('Validate suggested mapping')}>
        <Button
          variant="contained"
          color="secondary"
          classes={{ root: classes.button }}
          onClick={handleAskValidateSuggestedMapping}
          startIcon={<CheckCircleOutlined />}
          size="small"
        >
          {t_i18n('Validate')}
        </Button>
      </Tooltip>
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleChangeView={handleSwitchView}
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
          dataList={filteredMappedEntities}
          globalCount={filteredMappedEntities.length}
          LineComponent={
            <ContainerStixCoreObjectsSuggestedMappingLine
              handleRemoveSuggestedMappingLine={handleRemoveSuggestedMappingLine}
            />
          }
          DummyLineComponent={ContainerStixCoreObjectsSuggestedMappingLineDummy}
          dataColumns={dataColumns}
          contentMappingCount={suggestedMappingCount}
          mappingCount = {filteredMappedEntities.length}
          height={height}
        />
      </ListLines>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={openValidate}
        keepMounted
        TransitionComponent={Transition}
        onClose={() => setOpenValidate(false)}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to validate the mapping of this content?')}
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
