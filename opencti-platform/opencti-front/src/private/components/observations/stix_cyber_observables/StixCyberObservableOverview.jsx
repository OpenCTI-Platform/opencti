import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Button from '@common/button/Button';
import Chip from '@mui/material/Chip';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@common/button/IconButton';
import { BrushOutlined, Delete } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import { graphql } from 'react-relay';
import Slide from '@mui/material/Slide';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import ItemScore from '../../../../components/ItemScore';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';
import ItemCreators from '../../../../components/ItemCreators';
import ItemAuthor from '../../../../components/ItemAuthor';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ItemCopy from '../../../../components/ItemCopy';
import ItemMarkings from '../../../../components/ItemMarkings';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
  standard_id: {
    padding: '5px 5px 5px 10px',
    fontFamily: 'Consolas, monaco, monospace',
    fontSize: 11,
    backgroundColor:
      theme.palette.mode === 'light'
        ? 'rgba(0, 0, 0, 0.02)'
        : 'rgba(255, 255, 255, 0.02)',
    lineHeight: '18px',
  },
});

const stixCyberObservableMutation = graphql`
  mutation StixCyberObservableOverviewMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixCyberObservableEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        x_opencti_stix_ids
      }
    }
  }
`;

class StixCyberObservableOverview extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openStixIds: false,
    };
  }

  handleToggleOpenStixIds() {
    this.setState({ openStixIds: !this.state.openStixIds });
  }

  deleteStixId(stixId) {
    const { stixCyberObservable } = this.props;
    const otherStixIds = stixCyberObservable.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixCyberObservable.standard_id && n !== stixId,
      otherStixIds,
    );
    commitMutation({
      mutation: stixCyberObservableMutation,
      variables: {
        id: this.props.stixCyberObservable.id,
        input: {
          key: 'x_opencti_stix_ids',
          value: stixIds,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The STIX ID has been removed')),
    });
  }

  render() {
    const { t, fldt, classes, stixCyberObservable } = this.props;
    const otherStixIds = stixCyberObservable.x_opencti_stix_ids || [];
    const stixIds = R.filter(
      (n) => n !== stixCyberObservable.standard_id,
      otherStixIds,
    );
    return (
      <>
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Marking')}
              </Typography>
              <ItemMarkings
                markingDefinitions={stixCyberObservable.objectMarking ?? []}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Score')}
              </Typography>
              <ItemScore score={stixCyberObservable.x_opencti_score} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Author')}
              </Typography>
              <ItemAuthor
                createdBy={stixCyberObservable.createdBy}
              />
              <StixCoreObjectLabelsView
                labels={stixCyberObservable.objectLabel}
                id={stixCyberObservable.id}
                marginTop={20}
                entity_type={stixCyberObservable.entity_type}
              />
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Observable type')}
              </Typography>
              <Chip
                classes={{ root: classes.chip }}
                style={{
                  backgroundColor: 'rgba(32, 58, 246, 0.08)',
                  color: '#203af6',
                  border: '1px solid #203af6',
                }}
                label={t(`entity_${stixCyberObservable.entity_type}`)}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creators')}
              </Typography>
              <ItemCreators creators={stixCyberObservable.creators ?? []} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Platform creation date')}
              </Typography>
              {fldt(stixCyberObservable.created_at)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Modification date')}
              </Typography>
              {fldt(stixCyberObservable.updated_at)}
              <div style={{ marginTop: 20 }}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Standard STIX ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <InformationOutline fontSize="small" color="primary" />
                  </Tooltip>
                </div>
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <div style={{ float: 'right', margin: '-5px 0 0 8px' }}>
                    <IconButton
                      aria-label="Close"
                      disableRipple={true}
                      size="small"
                      disabled={stixIds.length === 0}
                      onClick={this.handleToggleOpenStixIds.bind(this)}
                    >
                      <BrushOutlined
                        fontSize="small"
                        color={stixIds.length === 0 ? 'inherit' : 'secondary'}
                      />
                    </IconButton>
                  </div>
                </Security>
                <div className="clearfix" />
                <div className={classes.standard_id}>
                  <ItemCopy content={stixCyberObservable.standard_id} />
                </div>
              </div>
            </Grid>
          </Grid>
        </Paper>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.openStixIds}
          slots={{ transition: Transition }}
          onClose={this.handleToggleOpenStixIds.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Other STIX IDs')}</DialogTitle>
          <DialogContent dividers={true}>
            <List>
              {stixIds.map(
                (stixId) => stixId.length > 0 && (
                  <ListItem
                    key={stixId}
                    disableGutters={true}
                    dense={true}
                    secondaryAction={(
                      <IconButton
                        edge="end"
                        aria-label="delete"
                        onClick={this.deleteStixId.bind(this, stixId)}
                      >
                        <Delete />
                      </IconButton>
                    )}
                  >
                    <ListItemText primary={stixId} />
                  </ListItem>
                ),
              )}
            </List>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleToggleOpenStixIds.bind(this)}
            >
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

StixCyberObservableOverview.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableOverview);
