import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import IconButton from '@common/button/IconButton';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import { Add, Close } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Fab from '@mui/material/Fab';
import CircularProgress from '@mui/material/CircularProgress';
import { ConnectionHandler } from 'relay-runtime';
import Skeleton from '@mui/material/Skeleton';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { formatDate } from '../../../../utils/Time';
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

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
  },
  createButtonWithPadding: {
    position: 'fixed',
    bottom: 30,
    right: 240,
    zIndex: 1001,
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
});

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

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_stixCoreRelationships',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixCoreRelationshipCreationFromRelation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      step: 0,
      targetEntity: null,
      search: '',
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ step: 0, targetEntity: null, open: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const { isRelationReversed, entityId } = this.props;
    const { targetEntity } = this.state;
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
        if (typeof this.props.onCreate !== 'function') {
          const payload = store.getRootField('stixCoreRelationshipAdd');
          const newEdge = payload.setLinkedRecord(payload, 'node');
          const container = store.getRoot();
          sharedUpdater(
            store,
            container.getDataID(),
            this.props.paginationOptions,
            newEdge,
          );
        }
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
    });
  }

  handleResetSelection() {
    this.setState({ step: 0, targetEntity: null });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  handleSelectEntity(stixDomainObject) {
    this.setState({ step: 1, targetEntity: stixDomainObject });
  }

  renderFakeList() {
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
  }

  renderSelectEntity() {
    const { search } = this.state;
    const { classes, t, stixCoreObjectTypes, onlyObservables } = this.props;
    const stixDomainObjectsPaginationOptions = {
      search,
      types: stixCoreObjectTypes
        ? R.filter((n) => n !== 'Stix-Cyber-Observable', stixCoreObjectTypes)
        : null,
      orderBy: search.length > 0 ? null : 'created_at',
      orderMode: search.length > 0 ? null : 'desc',
    };
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={this.handleClose.bind(this)}
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Create a relationship')}
          </Typography>
          <div className={classes.search}>
            <SearchInput
              variant="inDrawer"
              onSubmit={this.handleSearch.bind(this)}
            />
          </div>
          <div className="clearfix" />
        </div>
        <div className={classes.containerList}>
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
                      handleSelect={this.handleSelectEntity.bind(this)}
                      data={props}
                    />
                  );
                }
                return this.renderFakeList();
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
              search: this.state.search,
              types: stixCoreObjectTypes,
              count: 50,
              orderBy: 'created_at',
              orderMode: 'desc',
            }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCoreRelationshipCreationFromRelationStixCyberObservablesLines
                    handleSelect={this.handleSelectEntity.bind(this)}
                    data={props}
                  />
                );
              }
              return !stixCoreObjectTypes
                || stixCoreObjectTypes.length === 0 ? (
                    this.renderFakeList()
                  ) : (
                    <div> &nbsp; </div>
                  );
            }}
          />
          <StixDomainObjectCreation
            display={this.state.open}
            inputValue={this.state.search}
            paginationOptions={stixDomainObjectsPaginationOptions}
            stixDomainObjectTypes={stixCoreObjectTypes}
          />
        </div>
      </div>
    );
  }

  renderForm(sourceEntity) {
    const { t, classes, isRelationReversed, allowedRelationshipTypes } = this.props;
    const { targetEntity } = this.state;
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
            <>
              <div className={classes.header}>
                <IconButton
                  aria-label="Close"
                  className={classes.closeButton}
                  onClick={this.handleClose.bind(this)}
                >
                  <Close fontSize="small" color="primary" />
                </IconButton>
                <Typography variant="h6">{t('Create a relationship')}</Typography>
              </div>
              <StixCoreRelationshipCreationForm
                fromEntities={[fromEntity]}
                toEntities={[toEntity]}
                relationshipTypes={relationshipTypes}
                handleResetSelection={this.handleResetSelection.bind(this)}
                onSubmit={this.onSubmit.bind(this)}
                handleClose={this.handleClose.bind(this)}
              />
            </>
          );
        }}
      </UserContext.Consumer>
    );
  }

  renderLoader() {
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
  }

  render() {
    const { classes, entityId, variant, paddingRight } = this.props;
    const { open, step } = this.state;
    return (
      <div>
        {variant === 'inLine' ? (
          <IconButton
            aria-label="Label"
            onClick={this.handleOpen.bind(this)}
            style={{ float: 'left', margin: '-6px 0 10px 4px' }}
            size="small"
            variant="tertiary"
          >
            <Add />
          </IconButton>
        ) : (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="primary"
            aria-label="Add"
            className={
              paddingRight
                ? classes.createButtonWithPadding
                : classes.createButton
            }
          >
            <Add />
          </Fab>
        )}
        <Drawer
          open={open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: this.props.classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <QueryRenderer
            query={stixCoreRelationshipCreationFromRelationQuery}
            variables={{ id: entityId }}
            render={({ props }) => {
              if (props && props.stixCoreRelationship) {
                return (
                  <div style={{ height: '100%' }}>
                    {step === 0 ? this.renderSelectEntity() : ''}
                    {step === 1
                      ? this.renderForm(props.stixCoreRelationship)
                      : ''}
                  </div>
                );
              }
              return this.renderLoader();
            }}
          />
        </Drawer>
      </div>
    );
  }
}

StixCoreRelationshipCreationFromRelation.propTypes = {
  entityId: PropTypes.string,
  onlyObservables: PropTypes.bool,
  isRelationReversed: PropTypes.bool,
  stixCoreObjectTypes: PropTypes.array,
  allowedRelationshipTypes: PropTypes.array,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  variant: PropTypes.string,
  onCreate: PropTypes.func,
  paddingRight: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipCreationFromRelation);
