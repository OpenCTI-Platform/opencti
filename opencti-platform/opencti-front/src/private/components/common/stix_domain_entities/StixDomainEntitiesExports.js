import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Slide from '@material-ui/core/Slide';
import { createRefetchContainer } from 'react-relay';
import List from '@material-ui/core/List';
import { interval } from 'rxjs';
import Drawer from '@material-ui/core/Drawer';
import ListSubheader from '@material-ui/core/ListSubheader';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import StixDomainEntitiesExportCreation from './StixDomainEntitiesExportCreation';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from '../files/FileLine';
import inject18n from '../../../../components/i18n';

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
    margin: '2px -18px 0 0',
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

class StixDomainEntitiesExportsComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch({ type: this.props.exportEntityType });
    });
  }

  render() {
    const {
      classes,
      t,
      data,
      exportEntityType,
      paginationOptions,
      open,
      handleToggle,
    } = this.props;
    const stixDomainEntitiesExportFiles = pathOr(
      [],
      ['stixDomainEntitiesExportFiles', 'edges'],
      data,
    );
    return (
        <Drawer
          variant="persistent"
          open={open}
          anchor="right"
          classes={{ root: classes.drawer, paper: classes.drawerPaper }}
          onClose={handleToggle.bind(this)}
        >
          <div className={classes.toolbar} />
          <List
            subheader={
              <ListSubheader component="div">
                <div style={{ float: 'left' }}>{t('Exports list')}</div>
                <StixDomainEntitiesExportCreation
                  data={data}
                  exportEntityType={exportEntityType}
                  paginationOptions={paginationOptions}
                />
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
            {stixDomainEntitiesExportFiles.length > 0 ? (
              stixDomainEntitiesExportFiles.map((file) => (
                <FileLine
                  key={file.node.id}
                  file={file.node}
                  dense={true}
                  disableImport={true}
                  directDownload={true}
                />
              ))
            ) : (
              <div style={{ paddingLeft: 16 }}>
                {t('No file for the moment')}
              </div>
            )}
          </List>
        </Drawer>
    );
  }
}

export const stixDomainEntitiesExportsQuery = graphql`
  query StixDomainEntitiesExportsRefetchQuery($count: Int!, $type: String!) {
    ...StixDomainEntitiesExports_data @arguments(count: $count, type: $type)
  }
`;

const StixDomainEntitiesExports = createRefetchContainer(
  StixDomainEntitiesExportsComponent,
  {
    data: graphql`
      fragment StixDomainEntitiesExports_data on Query
        @argumentDefinitions(
          count: { type: "Int", defaultValue: 25 }
          type: { type: "String!" }
        ) {
        stixDomainEntitiesExportFiles(first: $count, type: $type)
          @connection(key: "Pagination_stixDomainEntitiesExportFiles") {
          edges {
            node {
              id
              ...FileLine_file
            }
          }
        }
        ...StixDomainEntitiesExportCreation_data
      }
    `,
  },
  stixDomainEntitiesExportsQuery,
);

StixDomainEntitiesExports.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  data: PropTypes.object,
  exportEntityType: PropTypes.string.isRequired,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntitiesExports);
