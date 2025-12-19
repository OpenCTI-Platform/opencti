import React, { useEffect, useState, ChangeEvent, SyntheticEvent } from 'react';
import { graphql } from 'react-relay';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { AddOutlined, MoveToInboxOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import IconButton from '@common/button/IconButton';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import InputAdornment from '@mui/material/InputAdornment';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import {
  type BackgroundTaskActionInput,
  type StixCoreObjectContainerTaskAddMutation,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContainerTaskAddMutation.graphql';
import { AutocompleteInputChangeReason } from '@mui/material/useAutocomplete/useAutocomplete';
import { StixCoreObjectContainerContainersQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContainerContainersQuery.graphql';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import Transition from '../../../../components/Transition';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import useDraftContext from '../../../../utils/hooks/useDraftContext';

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
  const handleChangeIncludeNeighboursOption = (event: ChangeEvent<HTMLInputElement>) => setIncludeNeighbours(event.target.checked);

  const handleSearch = (_: SyntheticEvent, newValue: string, reason: AutocompleteInputChangeReason) => {
    if (reason === 'reset') return;
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
          style={{ marginRight: 3 }}
        >
          <MoveToInboxOutlined color="primary" fontSize="small" />
        </ToggleButton>
      </Tooltip>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        fullWidth={true}
        maxWidth="sm"
        slots={{ transition: Transition }}
        open={displayAddInContainer}
        onClose={handleToggleAddInContainer(false)}
      >
        <DialogTitle>{t_i18n('Add in container')}</DialogTitle>
        <DialogContent>
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
          <Autocomplete
            sx={{
              '.MuiAutocomplete-inputRoot.MuiInput-root': {
                pr: '50px',
              },
            }}
            size="small"
            fullWidth
            selectOnFocus
            autoHighlight
            filterOptions={(options) => options} // used to block internal filtering of the material-ui component
            value={selectedContainers}
            multiple
            renderInput={(params) => (
              <TextField
                {...params}
                variant="standard"
                label={t_i18n('Values')}
                fullWidth={true}
                slotProps={{
                  input: {
                    ...params.InputProps,
                    endAdornment: (
                      <>
                        <InputAdornment position="end">
                          <IconButton
                            onClick={handleToggleContainerCreationDrawer(true)}
                            size="small"
                          >
                            <AddOutlined />
                          </IconButton>
                        </InputAdornment>
                        {params.InputProps.endAdornment}
                      </>
                    ),
                  },
                }}
              />
            )}
            noOptionsText={t_i18n('No available options')}
            options={optionList}
            onInputChange={handleSearch}
            inputValue={searchInputValue}
            onChange={(_, currentSelectedOptions: OptionListType[]) => handleChangeActionInputValues(currentSelectedOptions)}
            renderOption={(props, option) => (
              <li {...props} key={option.id}>
                <div style={{ padding: '4px' }}>
                  <ItemIcon type={option.type} />
                </div>
                <div style={{ marginLeft: 10 }}>{option.label}</div>
              </li>
            )}
            disableClearable
          />
          <FormControlLabel
            style={{ marginTop: 20 }}
            control={(
              <Checkbox
                checked={includeNeighbours}
                onChange={handleChangeIncludeNeighboursOption}
              />
            )}
            label={t_i18n('Also include first neighbours')}
          />
        </DialogContent>
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
