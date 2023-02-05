import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Slide from '@mui/material/Slide';
import { graphql, createRefetchContainer } from 'react-relay';
import List from '@mui/material/List';
import { interval } from 'rxjs';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import StixCoreRelationshipsExportCreation from './StixCoreRelationshipsExportCreation';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from '../files/FileLine';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT } from '../../../../utils/hooks/useGranted';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
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
});

class StixCoreRelationshipsExportsContentComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      if (this.props.isOpen) {
        this.props.relay.refetch({
          type: this.props.exportEntityType,
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
      exportEntityType,
      paginationOptions,
      handleToggle,
      context,
    } = this.props;
    const stixCoreRelationshipsExportFiles = pathOr(
      [],
      ['stixCoreRelationshipsExportFiles', 'edges'],
      data,
    );
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleToggle.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Exports list')}</Typography>
        </div>
        <List>
          {stixCoreRelationshipsExportFiles.length > 0 ? (
            stixCoreRelationshipsExportFiles.map((file) => (
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
        <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
          <StixCoreRelationshipsExportCreation
            data={data}
            exportEntityType={exportEntityType}
            paginationOptions={paginationOptions}
            context={context}
            onExportAsk={() => this.props.relay.refetch({
              type: this.props.exportEntityType,
              count: 25,
            })
            }
          />
        </Security>
      </div>
    );
  }
}

export const stixCoreRelationshipsExportsContentQuery = graphql`
  query StixCoreRelationshipsExportsContentRefetchQuery(
    $count: Int!
    $type: String!
  ) {
    ...StixCoreRelationshipsExportsContent_data
      @arguments(count: $count, type: $type)
  }
`;

const StixCoreRelationshipsExportsContent = createRefetchContainer(
  StixCoreRelationshipsExportsContentComponent,
  {
    data: graphql`
      fragment StixCoreRelationshipsExportsContent_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        type: { type: "String!" }
      ) {
        stixCoreRelationshipsExportFiles(first: $count, type: $type)
          @connection(key: "Pagination_stixCoreRelationshipsExportFiles") {
          edges {
            node {
              id
              ...FileLine_file
            }
          }
        }
        ...StixCoreRelationshipsExportCreation_data
      }
    `,
  },
  stixCoreRelationshipsExportsContentQuery,
);

StixCoreRelationshipsExportsContent.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  handleToggle: PropTypes.func,
  data: PropTypes.object,
  exportEntityType: PropTypes.string.isRequired,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  isOpen: PropTypes.bool,
  context: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipsExportsContent);
