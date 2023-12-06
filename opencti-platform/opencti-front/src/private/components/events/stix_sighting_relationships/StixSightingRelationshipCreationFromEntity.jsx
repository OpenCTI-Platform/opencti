import React, { useState } from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import { assoc, pipe, pluck } from 'ramda';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { Button } from '@mui/material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { dayStartDate, formatDate } from '../../../../utils/Time';
import StixSightingRelationshipCreationFromEntityStixDomainObjectsLines, {
  stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
} from './StixSightingRelationshipCreationFromEntityStixDomainObjectsLines';
import StixSightingRelationshipCreationFromEntityStixCyberObservablesLines, {
  stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery,
} from './StixSightingRelationshipCreationFromEntityStixCyberObservablesLines';
import StixDomainObjectCreation from '../../common/stix_domain_objects/StixDomainObjectCreation';
import SearchInput from '../../../../components/SearchInput';
import StixSightingRelationshipCreationForm from './StixSightingRelationshipCreationForm';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import Drawer from '../../common/drawer/Drawer';

const useStyles = makeStyles(() => ({
  search: {
    float: 'right',
  },
  container: {
    padding: 0,
    height: '100%',
    width: '100%',
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
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [targetEntity, setTargetEntity] = useState(null);
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [search, setSearch] = useState('');

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
    commitMutation({
      mutation: stixSightingRelationshipCreationFromEntityMutation,
      variables: { input: finalValues },
      updater: (store) => {
        if (typeof onCreate !== 'function') {
          insertNode(store, 'Pagination_stixSightingRelationships', paginationOptions, 'stixSightingRelationshipAdd');
        }
      },
      setSubmitting,
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

  // eslint-disable-next-line class-methods-use-this
  const renderFakeList = () => {
    return (
      <List>
        {Array.from(Array(20), (e, i) => (
          <ListItem key={i} divider={true} button={false}>
            <ListItemIcon>
              <Skeleton
                animation="wave"
                variant="circular"
                width={30}
                height={30}
              />
            </ListItemIcon>
            <ListItemText
              primary={
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={15}
                  style={{ marginBottom: 10 }}
                />
              }
              secondary={
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={15}
                />
              }
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

    const stixDomainObjectsPaginationOptions = {
      search,
      types: stixCoreObjectTypes,
      orderBy: 'created_at',
      orderMode: 'desc',
    };

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
        <StixDomainObjectCreation
          display={open}
          inputValue={search}
          paginationOptions={stixDomainObjectsPaginationOptions}
          stixDomainObjectTypes={stixCoreObjectTypes}
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
      <div style={{ height: '100%' }}>
        <div className={classes.container}>
          {search.length === 0 && (
            <Alert
              severity="info"
              variant="outlined"
              style={{ margin: '15px 15px 0 15px' }}
              classes={{ message: classes.info }}
            >
              {t_i18n(
                'This panel shows by default the latest created entities, use the search to find more.',
              )}
            </Alert>
          )}
          {renderSearchResults()}
        </div>
      </div>
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
      <>
        <StixSightingRelationshipCreationForm
          fromEntities={[fromEntity]}
          toEntities={[toEntity]}
          handleResetSelection={handleResetSelection}
          onSubmit={onSubmit}
          handleClose={handleClose}
          defaultFirstSeen={dayStartDate()}
          defaultLastSeen={dayStartDate()}
        />
      </>
    );
  };

  // eslint-disable-next-line
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
  return (
    <div>
      {variant === 'inLine' ? (
        <IconButton
          color="secondary"
          aria-label="Label"
          onClick={handleOpen}
          style={{ float: 'left', margin: '-15px 0 0 -2px' }}
          size="large"
        >
          <Add fontSize="small" />
        </IconButton>
      ) : ''}
      <Drawer
        title={<div>
          {t_i18n('Create a sighting')}
          {step === 0
            && <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                keyword={search}
                onSubmit={handleSearch}
              />
            </div>
          }
        </div>}
        controlledDial={({ onOpen }) => (
          <Button
            onClick={onOpen}
            style={{
              marginLeft: '3px',
              fontSize: 'small',
            }}
            variant='contained'
            disableElevation
          >
            {t_i18n('Create')} {t_i18n('entity_Sighting')} <Add />
          </Button>
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
