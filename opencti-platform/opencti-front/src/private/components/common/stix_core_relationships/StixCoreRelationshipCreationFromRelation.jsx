import React, { useState } from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import CircularProgress from '@mui/material/CircularProgress';
import Skeleton from '@mui/material/Skeleton';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { formatDate } from '../../../../utils/Time';
import { insertNode } from '../../../../utils/store';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import StixCoreRelationshipCreationFromRelationStixDomainObjectsLines, {
  stixCoreRelationshipCreationFromRelationStixDomainObjectsLinesQuery,
} from './StixCoreRelationshipCreationFromRelationStixDomainObjectsLines';
import StixCoreRelationshipCreationFromRelationStixCyberObservablesLines, {
  stixCoreRelationshipCreationFromRelationStixCyberObservablesLinesQuery,
} from './StixCoreRelationshipCreationFromRelationStixCyberObservablesLines';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import SearchInput from '../../../../components/SearchInput';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { UserContext } from '../../../../utils/hooks/useAuth';
import Drawer from '../drawer/Drawer';
import { Stack } from '@mui/material';

const stixCoreRelationshipCreationFromRelationQuery = graphql`
  query StixCoreRelationshipCreationFromRelationQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      id
      entity_type
      parent_types
      relationship_type
      description
      from {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
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
        ... on MalwareAnalysis {
          result_name
        }
        ... on DataComponent {
          name
        }
        ... on DataSource {
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
      to {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
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
        ... on MalwareAnalysis {
          result_name
        }
        ... on DataComponent {
          name
        }
        ... on DataSource {
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
  }
`;

const stixCoreRelationshipCreationFromRelationFromMutation = graphql`
  mutation StixCoreRelationshipCreationFromRelationFromMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      ...EntityStixCoreRelationshipLineFrom_node
    }
  }
`;

const stixCoreRelationshipCreationFromRelationToMutation = graphql`
  mutation StixCoreRelationshipCreationFromRelationToMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      ...EntityStixCoreRelationshipLineTo_node
    }
  }
`;

const StixCoreRelationshipCreationFromRelation = ({
  entityId,
  onlyObservables,
  isRelationReversed,
  stixCoreObjectTypes,
  allowedRelationshipTypes,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [targetEntity, setTargetEntity] = useState(null);
  const [search, setSearch] = useState('');

  const handleOpen = () => setOpen(true);

  const handleClose = () => {
    setStep(0);
    setTargetEntity(null);
    setOpen(false);
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const fromEntityId = isRelationReversed ? targetEntity.id : entityId;
    const toEntityId = isRelationReversed ? entityId : targetEntity.id;
    const finalValues = R.pipe(
      R.assoc('confidence', parseInt(values.confidence, 10)),
      R.assoc('fromId', fromEntityId),
      R.assoc('toId', toEntityId),
      R.assoc('start_time', formatDate(values.start_time)),
      R.assoc('stop_time', formatDate(values.stop_time)),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc(
        'externalReferences',
        R.pluck('value', values.externalReferences),
      ),
    )(values);
    commitMutation({
      mutation: isRelationReversed
        ? stixCoreRelationshipCreationFromRelationToMutation
        : stixCoreRelationshipCreationFromRelationFromMutation,
      variables: { input: finalValues },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_stixCoreRelationships',
          paginationOptions,
          'stixCoreRelationshipAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  const handleResetSelection = () => {
    setStep(0);
    setTargetEntity(null);
  };

  const handleSearch = (keyword) => setSearch(keyword);

  const handleSelectEntity = (stixDomainObject) => {
    setStep(1);
    setTargetEntity(stixDomainObject);
  };

  const renderFakeList = () => (
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

  const renderSelectEntity = () => {
    const stixDomainObjectsPaginationOptions = {
      search,
      types: stixCoreObjectTypes
        ? stixCoreObjectTypes.filter((n) => n !== 'Stix-Cyber-Observable')
        : null,
      orderBy: search.length > 0 ? null : 'created_at',
      orderMode: search.length > 0 ? null : 'desc',
    };
    return (
      <Stack>
        {!onlyObservables ? (
          <QueryRenderer
            query={
              stixCoreRelationshipCreationFromRelationStixDomainObjectsLinesQuery
            }
            variables={{ count: 25, ...stixDomainObjectsPaginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCoreRelationshipCreationFromRelationStixDomainObjectsLines
                    handleSelect={handleSelectEntity}
                    data={props}
                  />
                );
              }
              return renderFakeList();
            }}
          />
        ) : (
          ''
        )}
        <QueryRenderer
          query={
            stixCoreRelationshipCreationFromRelationStixCyberObservablesLinesQuery
          }
          variables={{
            search,
            types: stixCoreObjectTypes,
            count: 50,
            orderBy: 'created_at',
            orderMode: 'desc',
          }}
          render={({ props }) => {
            if (props) {
              return (
                <StixCoreRelationshipCreationFromRelationStixCyberObservablesLines
                  handleSelect={handleSelectEntity}
                  data={props}
                />
              );
            }
            return !stixCoreObjectTypes
              || stixCoreObjectTypes.length === 0 ? (
                  renderFakeList()
                ) : (
                  <div> &nbsp; </div>
                );
          }}
        />
        <Stack direction="row" alignSelf="flex-end">
          <StixDomainObjectCreation
            display={open}
            inputValue={search}
            paginationOptions={stixDomainObjectsPaginationOptions}
            stixDomainObjectTypes={stixCoreObjectTypes}
          />
        </Stack>
      </Stack>
    );
  };

  const renderForm = (sourceEntity) => {
    let fromEntity = sourceEntity;
    let toEntity = targetEntity;
    if (isRelationReversed) {
      fromEntity = targetEntity;
      toEntity = sourceEntity;
    }

    return (
      <UserContext.Consumer>
        {({ schema }) => {
          const relationshipTypes = R.uniq(resolveRelationsTypes(
            fromEntity.parent_types.includes('Stix-Cyber-Observable')
              ? 'observable'
              : fromEntity.entity_type,
            toEntity.entity_type,
            schema.schemaRelationsTypesMapping,
          ).filter(
            (n) => R.isNil(allowedRelationshipTypes)
              || allowedRelationshipTypes.length === 0
              || allowedRelationshipTypes.includes(n),
          ));
          return (
            <StixCoreRelationshipCreationForm
              fromEntities={[fromEntity]}
              toEntities={[toEntity]}
              relationshipTypes={relationshipTypes}
              handleResetSelection={handleResetSelection}
              onSubmit={onSubmit}
              handleClose={handleClose}
            />
          );
        }}
      </UserContext.Consumer>
    );
  };

  const renderLoader = () => (
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

  return (
    <div>
      <IconButton
        aria-label={t_i18n('Add relationship')}
        onClick={handleOpen}
        size="small"
        variant="tertiary"
      >
        <Add />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Create a relationship')}
        subHeader={{
          left: step === 0
            ? [(
                <SearchInput
                  variant="inDrawer"
                  onSubmit={handleSearch}
                  key="leftInput"
                />
              )]
            : [],
        }}
      >
        <QueryRenderer
          query={stixCoreRelationshipCreationFromRelationQuery}
          variables={{ id: entityId }}
          render={({ props }) => {
            if (props && props.stixCoreRelationship) {
              return (
                <div style={{ marginTop: -20 }}>
                  {step === 0 ? renderSelectEntity() : ''}
                  {step === 1 ? renderForm(props.stixCoreRelationship) : ''}
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

export default StixCoreRelationshipCreationFromRelation;
