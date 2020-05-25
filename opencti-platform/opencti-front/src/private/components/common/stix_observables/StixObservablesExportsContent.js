import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Slide from '@material-ui/core/Slide';
import { createRefetchContainer } from 'react-relay';
import List from '@material-ui/core/List';
import { interval } from 'rxjs';
import ListSubheader from '@material-ui/core/ListSubheader';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import StixObservablesExportCreation from './StixObservablesExportCreation';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from '../files/FileLine';
import inject18n from '../../../../components/i18n';
import Security, {
  KNOWLEDGE_KNGETEXPORT_KNASKEXPORT,
} from '../../../../utils/Security';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 310,
    padding: '0 0 20px 0',
    overflowX: 'hidden',
    zIndex: 0,
    backgroundColor: theme.palette.navAlt.background,
  },
  buttonClose: {
    float: 'right',
    margin: '2px -16px 0 0',
  },
  listIcon: {
    marginRight: 0,
  },
  item: {
    padding: '0 0 0 10px',
  },
  itemField: {
    padding: '0 15px 0 15px',
  },
  toolbar: theme.mixins.toolbar,
});

class StixObservablesExportsContentComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      if (this.props.isOpen) {
        this.props.relay.refetch({
          count: 25,
        });
      }
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const {
      classes,
      t,
      data,
      paginationOptions,
      handleToggle,
      context,
    } = this.props;
    const stixObservablesExportFiles = pathOr(
      [],
      ['stixObservablesExportFiles', 'edges'],
      data,
    );
    return (
      <List
        subheader={
          <ListSubheader component="div">
            <div style={{ float: 'left' }}>{t('Exports list')}</div>
            <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
              <StixObservablesExportCreation
                data={data}
                paginationOptions={paginationOptions}
                context={context}
              />
            </Security>
            <IconButton
              color="inherit"
              classes={{ root: classes.buttonClose }}
              onClick={handleToggle.bind(this)}
            >
              <Close />
            </IconButton>
            <div className="clearfix" />
          </ListSubheader>
        }
      >
        {stixObservablesExportFiles.length > 0 ? (
          stixObservablesExportFiles.map((file) => (
            <FileLine
              key={file.node.id}
              file={file.node}
              dense={true}
              disableImport={true}
              directDownload={true}
            />
          ))
        ) : (
          <div style={{ paddingLeft: 16 }}>{t('No file for the moment')}</div>
        )}
      </List>
    );
  }
}

export const stixObservablesExportsContentQuery = graphql`
  query StixObservablesExportsContentRefetchQuery(
    $count: Int!
    $context: String
  ) {
    ...StixObservablesExportsContent_data
      @arguments(count: $count, context: $context)
  }
`;

const StixObservablesExportsContent = createRefetchContainer(
  StixObservablesExportsContentComponent,
  {
    data: graphql`
      fragment StixObservablesExportsContent_data on Query
        @argumentDefinitions(
          count: { type: "Int", defaultValue: 25 }
          context: { type: "String!" }
        ) {
        stixObservablesExportFiles(first: $count, context: $context)
          @connection(key: "Pagination_stixObservablesExportFiles") {
          edges {
            node {
              id
              ...FileLine_file
            }
          }
        }
        ...StixObservablesExportCreation_data
      }
    `,
  },
  stixObservablesExportsContentQuery,
);

StixObservablesExportsContent.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  handleToggle: PropTypes.func,
  data: PropTypes.object,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  isOpen: PropTypes.bool,
  context: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservablesExportsContent);
