import {
  Checkbox,
  Combobox,
  ComboboxChips,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  type ComboboxChangeMeta,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { StixCoreObjectContainerContainersQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContainerContainersQuery.graphql';
import {
  type BackgroundTaskActionInput,
  type StixCoreObjectContainerTaskAddMutation,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContainerTaskAddMutation.graphql';
import { AddOutlined, MoveToInboxOutlined } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';

const stixCoreObjectContainerTaskAddMutation = graphql`
  mutation StixCoreObjectContainerTaskAddMutation($input: ListTaskAddInput!) {
    listTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const stixCoreObjectContainerContainersQuery = graphql`
  query StixCoreObjectContainerContainersQuery($search: String) {
    containers(search: $search) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

type StixCoreObjectContainerProps = {
  elementId: string;
};

type OptionListType = {
  label: string;
  type: string;
  id: string;
};

type StixDomainObjectCreationCallbackType = {
  id: string;
  entity_type: string;
  representative?: {
    main: string;
  };
  name: string;
};

const StixCoreObjectContainer = ({ elementId }: StixCoreObjectContainerProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();

  const [processing, setProcessing] = useState<boolean>(false);
  const [displayAddInContainer, setDisplayAddInContainer] = useState<boolean>(false);
  const [isContainerCreationDrawerOpen, setIsContainerCreationDrawerOpen] = useState<boolean>(false);

  const [optionList, setOptionList] = useState<OptionListType[]>([]);
  const [selectedContainers, setSelectedContainers] = useState<OptionListType[]>([]);
  const [includeNeighbours, setIncludeNeighbours] = useState<boolean>();
  const [searchInputValue, setSearchInputValue] = useState<string>('');

  const fetchContainerList = (search: string) => {
    fetchQuery(stixCoreObjectContainerContainersQuery, {
      search,
    })
      .toPromise()
      .then((data) => {
        const stixCoreObjectContainer = data as StixCoreObjectContainerContainersQuery$data;
        const newContainerList = stixCoreObjectContainer.containers?.edges?.map?.((edge) => ({
          label: edge?.node.representative.main ?? '',
          type: edge?.node.entity_type ?? '',
          id: edge?.node.id ?? '',
        })) ?? [];
        setOptionList([...newContainerList]);
      });
  };

  useEffect(() => {
    const timeoutId = setTimeout(() => {
      fetchContainerList(searchInputValue);
    }, 500);
    return () => clearTimeout(timeoutId);
  }, [searchInputValue]);

  const handleToggleAddInContainer = (isOpen: boolean) => () => setDisplayAddInContainer(isOpen);
  const handleToggleContainerCreationDrawer = (isOpen: boolean) => () => setIsContainerCreationDrawerOpen(isOpen);

  const handleChangeActionInputValues = (values: OptionListType[]) => setSelectedContainers(values);
  const handleChangeIncludeNeighboursOption = (checked: boolean | 'indeterminate') => setIncludeNeighbours(checked === true);

  // 'reset' was MUI's word for the engine re-syncing the text to the selection;
  // the library reports that as cause 'reset' too, so the guard is unchanged.
  const handleSearch = (newValue: string, meta: ComboboxChangeMeta) => {
    if (meta.cause === 'reset') return;
    setSearchInputValue(newValue);
  };

  const [commit] = useApiMutation<StixCoreObjectContainerTaskAddMutation>(stixCoreObjectContainerTaskAddMutation);

  const handleLaunchUpdate = () => {
    setProcessing(true);
    const finalActions: BackgroundTaskActionInput = {
      type: 'ADD',
      context: {
        field: 'container-object',
        type: 'ATTRIBUTE',
        values: selectedContainers.map((container) => container.id),
        options: {
          includeNeighbours,
        },
      },
    };

    commit({
      variables: {
        input: {
          ids: [elementId],
          actions: [finalActions],
          scope: 'KNOWLEDGE',
        },
      },
      onCompleted: () => {
        setProcessing(false);
        setDisplayAddInContainer(false);
        setSelectedContainers([]);
        setIncludeNeighbours(false);
        const monitoringLink = !draftContext ? <Link to="/dashboard/data/processing/tasks">{t_i18n('the dedicated page')}</Link> : t_i18n('the draft processes tab');
        MESSAGING$.notifySuccess(
          <span>
            {t_i18n('The background task has been executed. You can monitor it on')}{' '}
            {monitoringLink}
            .
          </span>,
        );
      },
    });
  };

  return (
    <>
      <Tooltip title={t_i18n('Add in container')}>
        <ToggleButton
          onClick={handleToggleAddInContainer(true)}
          value="container"
          size="small"
        >
          <MoveToInboxOutlined color="primary" fontSize="small" />
        </ToggleButton>
      </Tooltip>
      <Dialog
        open={displayAddInContainer}
        onClose={handleToggleAddInContainer(false)}
        title={t_i18n('Add in container')}
      >
        <StixDomainObjectCreation
          inputValue={searchInputValue}
          open={isContainerCreationDrawerOpen}
          display={true}
          speeddial={true}
          stixDomainObjectTypes={['Container']}
          handleClose={handleToggleContainerCreationDrawer(false)}
          creationCallback={(data: StixDomainObjectCreationCallbackType) => {
            const newContainer: OptionListType = {
              label: data.representative?.main ? data.representative.main : data.name,
              id: data.id,
              type: data.entity_type,
            };
            setOptionList([...optionList, newContainer]);
            handleChangeActionInputValues([...selectedContainers, newContainer]);
          }}
          confidence={undefined}
          defaultCreatedBy={undefined}
          onCompleted={undefined}
          defaultMarkingDefinitions={undefined}
          isFromBulkRelation={undefined}
          paginationKey={undefined}
          paginationOptions={undefined}
        />
        <Combobox<OptionListType>
          className="w-full"
          selectOnFocus
          multiple
          clearable={false}
          filterOptions={(options) => options}
          value={selectedContainers}
          options={optionList}
          inputValue={searchInputValue}
          onInputChange={handleSearch}
          onValueChange={(next) => handleChangeActionInputValues((next ?? []) as OptionListType[])}
          renderOption={(option) => (
            <>
              <div style={{ padding: '4px' }}>
                <ItemIcon type={option.type} />
              </div>
              <div style={{ marginLeft: 10 }}>{option.label}</div>
            </>
          )}
          getOptionLabel={(option) => option.label}
        >
          <ComboboxLabel>{t_i18n('Values')}</ComboboxLabel>
          {/* #155: the create control is interactive, so it takes the
              host-owned `adornment` slot. */}
          <ComboboxField adornment={(
            <IconButton
              aria-label={t_i18n('Create')}
              onClick={handleToggleContainerCreationDrawer(true)}
              size="small"
            >
              <AddOutlined />
            </IconButton>
          )}
          >
            <ComboboxChips aria-label={t_i18n('Values')} />
            <ComboboxInput />
            <ComboboxControls>
              <ComboboxTrigger />
            </ComboboxControls>
          </ComboboxField>
          <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={t_i18n('Values')} />
        </Combobox>
        <div style={{ marginTop: 20 }}>
          <Checkbox
            checked={includeNeighbours}
            onCheckedChange={handleChangeIncludeNeighboursOption}
            label={t_i18n('Also include first neighbours')}
          />
        </div>
        <DialogActions>
          <Button variant="secondary" onClick={handleToggleAddInContainer(false)}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleLaunchUpdate}
            disabled={processing || selectedContainers.length === 0}
          >
            {t_i18n('Add')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default StixCoreObjectContainer;
