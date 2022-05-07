import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { BrushOutlined, Delete } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import Slide from '@mui/material/Slide';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import ItemScore from '../../../../components/ItemScore';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';
import ItemCreator from '../../../../components/ItemCreator';
import ItemAuthor from '../../../../components/ItemAuthor';
import inject18n from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: '0',
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
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
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
              <div className="clearfix" />
              <pre style={{ margin: 0 }}>{stixCyberObservable.standard_id}</pre>
            </Grid>
            <Grid item={true} xs={6}>
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
                {t('Score')}
              </Typography>
              <ItemScore score={stixCyberObservable.x_opencti_score} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('STIX version')}
              </Typography>
              <Button
                variant="outlined"
                size="small"
                style={{ cursor: 'default' }}
              >
                {stixCyberObservable.spec_version}
              </Button>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Author')}
              </Typography>
              <ItemAuthor
                createdBy={propOr(null, 'createdBy', stixCyberObservable)}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <StixCoreObjectLabelsView
                labels={stixCyberObservable.objectLabel}
                id={stixCyberObservable.id}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creator')}
              </Typography>
              <ItemCreator creator={stixCyberObservable.creator} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creation date')}
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
            </Grid>
          </Grid>
        </Paper>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.openStixIds}
          TransitionComponent={Transition}
          onClose={this.handleToggleOpenStixIds.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Other STIX IDs')}</DialogTitle>
          <DialogContent dividers={true}>
            <List>
              {stixIds.map(
                (stixId) => stixId.length > 0 && (
                    <ListItem key={stixId} disableGutters={true} dense={true}>
                      <ListItemText primary={stixId} />
                      <ListItemSecondaryAction>
                        <IconButton
                          edge="end"
                          aria-label="delete"
                          onClick={this.deleteStixId.bind(this, stixId)}
                          size="large"
                        >
                          <Delete />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                ),
              )}
            </List>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleToggleOpenStixIds.bind(this)}
              color="primary"
            >
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
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
