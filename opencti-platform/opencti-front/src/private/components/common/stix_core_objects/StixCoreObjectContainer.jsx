import React, { useState } from 'react';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { AddOutlined, MoveToInboxOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import IconButton from '@mui/material/IconButton';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import * as R from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import Transition from '../../../../components/Transition';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../../relay/environment';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

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

const StixCoreObjectContainer = ({ elementId }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [actionsInputs, setActionsInputs] = useState([
    { type: 'ADD', fieldType: 'ATTRIBUTE', field: 'container-object' },
  ]);
  const [searchInputValue, setSearchInputValue] = useState('');
  const [processing, setProcessing] = useState(false);
  const [containers, setContainers] = useState([]);
  const [displayAddInContainer, setDisplayAddInContainer] = useState(false);
  const [containerCreation, setContainerCreation] = useState(false);
  const handleChangeActionInputValues = (event, value) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    setActionsInputs([
      R.assoc(
        'values',
        Array.isArray(value) ? value : [value],
        actionsInputs[0] || {},
      ),
    ]);
  };
  const handleChangeActionInputOptions = (key, event) => {
    setActionsInputs([
      R.assoc(
        'options',
        R.assoc(key, event.target.checked, actionsInputs[0]?.options || {}),
        actionsInputs[0] || {},
      ),
    ]);
  };
  const searchContainers = (event, newValue) => {
    if (!event) return;
    setSearchInputValue(newValue);
    fetchQuery(stixCoreObjectContainerContainersQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const elements = data.containers.edges.map((e) => e.node);
        setContainers(
          elements.map((n) => ({
            label: n.representative.main,
            type: n.entity_type,
            value: n.id,
          })),
        );
      });
  };
  const handleLaunchUpdate = () => {
    setProcessing(true);
    const finalActions = R.map(
      (n) => ({
        type: n.type,
        context: {
          field: n.field,
          type: n.fieldType,
          values: R.map((o) => o.id || o.value || o, n.values),
          options: n.options,
        },
      }),
      actionsInputs,
    );
    commitMutation({
      mutation: stixCoreObjectContainerTaskAddMutation,
      variables: {
        input: {
          ids: [elementId],
          actions: finalActions,
          scope: 'KNOWLEDGE',
        },
      },
      onCompleted: () => {
        setProcessing(false);
        setDisplayAddInContainer(false);
        setActionsInputs([
          {
            type: 'ADD',
            fieldType: 'ATTRIBUTE',
            field: 'container-object',
          },
        ]);
        MESSAGING$.notifySuccess(
          <span>
            {t_i18n('The background task has been executed. You can monitor it on')}{' '}
            <Link to="/dashboard/data/processing/tasks">
              {t_i18n('the dedicated page')}
            </Link>
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
          onClick={() => setDisplayAddInContainer(true)}
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
        onClose={() => setDisplayAddInContainer(false)}
      >
        <DialogTitle>{t_i18n('Add in container')}</DialogTitle>
        <DialogContent>
          <StixDomainObjectCreation
            inputValue={actionsInputs[0]?.inputValue || ''}
            open={containerCreation}
            display={true}
            speeddial={true}
            stixDomainObjectTypes={['Container']}
            handleClose={() => setContainerCreation(false)}
            creationCallback={(data) => {
              const element = {
                label: data.name,
                value: data.id,
                type: data.entity_type,
              };
              setContainers([...containers, element]);
              handleChangeActionInputValues(null, [
                ...(actionsInputs[0]?.values ?? []),
                element,
              ]);
            }}
          />
          <Autocomplete
            sx={{
              '.MuiAutocomplete-inputRoot.MuiInput-root': {
                pr: '50px',
              },
            }}
            size="small"
            fullWidth={true}
            selectOnFocus={true}
            autoHighlight={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[0]?.values || []}
            multiple={true}
            renderInput={(params) => (
              <TextField
                {...params}
                variant="standard"
                label={t_i18n('Values')}
                fullWidth={true}
                onFocus={(e) => searchContainers(e)}
                style={{ marginTop: 3 }}
              />
            )}
            noOptionsText={t_i18n('No available options')}
            options={containers}
            onInputChange={(e, value) => searchContainers(e, value)}
            inputValue={searchInputValue ?? ''}
            onChange={(event, value) => handleChangeActionInputValues(event, value)
            }
            renderOption={(props, option) => (
              <li {...props}>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </li>
            )}
            disableClearable
          />
          <FormControlLabel
            style={{ marginTop: 20 }}
            control={
              <Checkbox
                checked={actionsInputs[0]?.options?.includeNeighbours || false}
                onChange={(event) => handleChangeActionInputOptions('includeNeighbours', event)
                }
              />
            }
            label={t_i18n('Also include first neighbours')}
          />
          <IconButton
            onClick={() => setContainerCreation(true)}
            edge="end"
            style={{ position: 'absolute', top: 68, right: 48 }}
            size="large"
          >
            <AddOutlined />
          </IconButton>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDisplayAddInContainer(false)}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={handleLaunchUpdate}
            disabled={
              processing || (actionsInputs[0].values ?? []).length === 0
            }
          >
            {t_i18n('Add')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default StixCoreObjectContainer;
