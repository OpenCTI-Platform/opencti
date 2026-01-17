import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import { Stack } from '@mui/material';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import Fab from '@mui/material/Fab';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import { assoc, pipe, pluck } from 'ramda';
import { useState } from 'react';
import { graphql } from 'react-relay';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { insertNode } from '../../../../utils/store';
import { dayStartDate, formatDate } from '../../../../utils/Time';
import Drawer from '../../common/drawer/Drawer';
import StixDomainObjectCreation from '../../common/stix_domain_objects/StixDomainObjectCreation';
import StixSightingRelationshipCreationForm from './StixSightingRelationshipCreationForm';
import StixSightingRelationshipCreationFromEntityStixCyberObservablesLines, {
  stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery,
} from './StixSightingRelationshipCreationFromEntityStixCyberObservablesLines';
import StixSightingRelationshipCreationFromEntityStixDomainObjectsLines, {
  stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
} from './StixSightingRelationshipCreationFromEntityStixDomainObjectsLines';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
  },
}));

const stixSightingRelationshipCreationFromEntityQuery = graphql`
  query StixSightingRelationshipCreationFromEntityQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      parent_types
      ... on AttackPattern {
        name
      }
      ... on Campaign {
        name
      }
      ... on CourseOfAction {
        name
      }
      ... on Individual {
        name
      }
      ... on Organization {
        name
      }
      ... on Sector {
        name
      }
      ... on System {
        name
      }
      ... on Indicator {
        name
      }
      ... on Infrastructure {
        name
      }
      ... on IntrusionSet {
        name
      }
      ... on Position {
        name
      }
      ... on City {
        name
      }
      ... on AdministrativeArea {
        name
      }
      ... on Country {
        name
      }
      ... on Region {
        name
      }
      ... on Malware {
        name
      }
      ... on ThreatActor {
        name
      }
      ... on Tool {
        name
      }
      ... on Vulnerability {
        name
      }
      ... on Incident {
        name
      }
      ... on StixCyberObservable {
        observable_value
      }
    }
  }
`;

const stixSightingRelationshipCreationFromEntityMutation = graphql`
  mutation StixSightingRelationshipCreationFromEntityMutation(
    $input: StixSightingRelationshipAddInput!
  ) {
    stixSightingRelationshipAdd(input: $input) {
      ...EntityStixSightingRelationshipLine_node
    }
  }
`;

const StixSightingRelationshipCreationFromEntity = ({
  isTo,
  entityId,
  onCreate,
  paginationOptions,
  stixCoreObjectTypes,
  variant,
  targetStixCyberObservableTypes,
  paddingRight,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [targetEntity, setTargetEntity] = useState(null);
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [search, setSearch] = useState('');
  const [commit] = useApiMutation(
    stixSightingRelationshipCreationFromEntityMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Sighting')} ${t_i18n('successfully created')}` },
  );
  const stixDomainObjectsPaginationOptions = {
    search,
    types: stixCoreObjectTypes,
    orderBy: 'created_at',
    orderMode: 'desc',
  };

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setStep(0);
    setTargetEntity(null);
    setOpen(false);
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const fromEntityId = isTo ? targetEntity.id : entityId;
    const toEntityId = isTo ? entityId : targetEntity.id;
    const finalValues = pipe(
      assoc('confidence', parseInt(values.confidence, 10)),
      assoc('attribute_count', parseInt(values.attribute_count, 10)),
      assoc('fromId', fromEntityId),
      assoc('toId', toEntityId),
      assoc('first_seen', formatDate(values.first_seen)),
      assoc('last_seen', formatDate(values.last_seen)),
      assoc('createdBy', values.createdBy?.value),
      assoc('objectMarking', pluck('value', values.objectMarking)),
      assoc(
        'externalReferences',
        R.pluck('value', values.externalReferences),
      ),
    )(values);
    commit({
      variables: { input: finalValues },
      updater: (store) => {
        if (typeof onCreate !== 'function') {
          insertNode(store, 'Pagination_stixSightingRelationships', paginationOptions, 'stixSightingRelationshipAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
        if (typeof onCreate === 'function') {
          onCreate();
        }
      },
    });
  };

  const handleResetSelection = () => {
    setStep(0);
    setTargetEntity(null);
  };

  const handleSearch = (keyword) => {
    setSearch(keyword);
  };

  const handleSelectEntity = (stixDomainObject) => {
    setStep(1);
    setTargetEntity(stixDomainObject);
  };

  const renderFakeList = () => {
    return (
      <List>
        {Array.from(Array(20), (e, i) => (
          <ListItem key={i} divider={true}>
            <ListItemIcon>
              <Skeleton
                animation="wave"
                variant="circular"
                width={30}
                height={30}
              />
            </ListItemIcon>
            <ListItemText
              primary={(
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={15}
                  style={{ marginBottom: 10 }}
                />
              )}
              secondary={(
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={15}
                />
              )}
            />
          </ListItem>
        ))}
      </List>
    );
  };

  const renderDomainObjectSearchResults = () => {
    if (!stixCoreObjectTypes || stixCoreObjectTypes.length === 0) {
      return null;
    }

    return (
      <div>
        <QueryRenderer
          query={
            stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery
          }
          variables={{
            count: 25,
            ...stixDomainObjectsPaginationOptions,
          }}
          render={({ props }) => {
            if (props) {
              return (
                <StixSightingRelationshipCreationFromEntityStixDomainObjectsLines
                  handleSelect={handleSelectEntity}
                  data={props}
                />
              );
            }
            return renderFakeList();
          }}
        />
      </div>
    );
  };

  const renderObservableSearchResults = () => {
    if (
      !targetStixCyberObservableTypes
      || targetStixCyberObservableTypes.length === 0
    ) {
      return null;
    }

    return (
      <QueryRenderer
        query={
          stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery
        }
        variables={{
          search,
          types: targetStixCyberObservableTypes,
          count: 50,
          orderBy: 'created_at',
          orderMode: 'desc',
        }}
        render={({ props }) => {
          if (props) {
            return (
              <StixSightingRelationshipCreationFromEntityStixCyberObservablesLines
                handleSelect={handleSelectEntity}
                data={props}
              />
            );
          }
          return stixCoreObjectTypes.length === 0 ? (
            renderFakeList()
          ) : (
            <div> &nbsp; </div>
          );
        }}
      />
    );
  };

  const renderSearchResults = () => {
    return (
      <div>
        {renderDomainObjectSearchResults()}
        {renderObservableSearchResults()}
      </div>
    );
  };

  const renderSelectEntity = () => {
    return (
      <Stack gap={2}>
        {search.length === 0 && (
          <Alert
            severity="info"
            variant="outlined"
            classes={{ message: classes.info }}
          >
            {t_i18n(
              'This panel shows by default the latest created entities, use the search to find more.',
            )}
          </Alert>
        )}
        <div>
          <SearchInput
            keyword={search}
            onSubmit={handleSearch}
          />
        </div>
        {renderSearchResults()}
      </Stack>
    );
  };

  const renderForm = (sourceEntity) => {
    let fromEntity = sourceEntity;
    let toEntity = targetEntity;
    if (isTo) {
      fromEntity = targetEntity;
      toEntity = sourceEntity;
    }
    return (
      <StixSightingRelationshipCreationForm
        fromEntities={[fromEntity]}
        toEntities={[toEntity]}
        handleResetSelection={handleResetSelection}
        onSubmit={onSubmit}
        handleClose={handleClose}
        defaultFirstSeen={dayStartDate()}
        defaultLastSeen={dayStartDate()}
      />
    );
  };

  const renderLoader = () => {
    return (
      <div style={{ display: 'table', height: '100%', width: '100%' }}>
        <span
          style={{
            display: 'table-cell',
            verticalAlign: 'middle',
            textAlign: 'center',
          }}
        >
          <CircularProgress size={80} thickness={2} />
        </span>
      </div>
    );
  };

  const openElement = () => {
    switch (variant) {
      case 'controlledDial':
        return (
          <CreateEntityControlledDial entityType="Sighting" onOpen={handleOpen} />
        );
      case 'inLine':
        return (
          <IconButton
            color="secondary"
            aria-label="Label"
            onClick={handleOpen}
            style={{ float: 'left', margin: '-15px 0 0 -2px' }}
          >
            <Add fontSize="small" />
          </IconButton>
        );
      default:
        return (
          <Fab
            onClick={handleOpen}
            color="secondary"
            aria-label="Add"
            className={classes.createButton}
            style={{ right: paddingRight || 30 }}
          >
            <Add />
          </Fab>
        );
    }
  };

  return (
    <div>
      {openElement()}
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Create a sighting')}
        header={step === 0 && (
          <StixDomainObjectCreation
            display={open}
            inputValue={search}
            paginationOptions={stixDomainObjectsPaginationOptions}
            stixDomainObjectTypes={stixCoreObjectTypes}
            controlledDialStyles={{ float: 'right' }}
            controlledDialSize="small"
          />
        )}
      >
        <QueryRenderer
          query={stixSightingRelationshipCreationFromEntityQuery}
          variables={{ id: entityId }}
          render={({ props }) => {
            if (props && props.stixCoreObject) {
              return (
                <div style={{ height: '100%' }}>
                  {step === 0 ? renderSelectEntity() : ''}
                  {step === 1 ? renderForm(props.stixCoreObject) : ''}
                </div>
              );
            }
            return renderLoader();
          }}
        />
      </Drawer>
    </div>
  );
};

export default StixSightingRelationshipCreationFromEntity;
