import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, Tooltip, Typography } from '@mui/material';
import { makeStyles } from '@mui/styles';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { truncate } from 'src/utils/String';
import { Create } from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { MESSAGING$, commitMutation, defaultCommitMutation } from 'src/relay/environment';
import StixCoreRelationshipEdition, { stixCoreRelationshipEditionDeleteMutation } from './StixCoreRelationshipEdition';
import { StixCoreRelationshipHeader_stixCoreRelationship$data } from './__generated__/StixCoreRelationshipHeader_stixCoreRelationship.graphql';

const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
    marginRight: 10,
  },
  editButton: {
    float: 'right',
    fontSize: 'small',
  },
}));

const StixCoreRelationshipHeaderOverview = ({
  stixCoreRelationship,
}: { stixCoreRelationship: StixCoreRelationshipHeader_stixCoreRelationship$data }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const navigate = useNavigate();
  const [openEdit, setOpenEdit] = useState(false);
  const [openDelete, setOpenDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const { id, from, relationship_type, to } = stixCoreRelationship;
  const relationName = t_i18n(`relationship_${relationship_type}`);
  const title = `${from?.name} ${relationName} ${to?.name}`;

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      ...defaultCommitMutation,
      mutation: stixCoreRelationshipEditionDeleteMutation,
      variables: { id },
      onError: (error: Error) => {
        MESSAGING$.notifyError(`${error}`);
      },
      onCompleted: () => {
        setDeleting(false);
        setOpenDelete(false);
        MESSAGING$.notifySuccess(t_i18n('Relationship successfully deleted'));
        navigate(location.pathname.replace(`/relations/${id}`, ''));
      },
    });
  };

  return (<>
    <Tooltip title={title}>
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
      >
        {truncate(title, 80)}
      </Typography>
    </Tooltip>
    <Button
      className={classes.editButton}
      variant='outlined'
      onClick={() => setOpenEdit(true)}
    >
      {t_i18n('Edit')} <Create />
    </Button>
    <div className="clearfix" />
    <StixCoreRelationshipEdition
      open={openEdit}
      stixCoreRelationshipId={id}
      handleClose={() => setOpenEdit(false)}
      handleDelete={() => setOpenDelete(true)}
      noStoreUpdate={undefined}
      inGraph={undefined}
    />
    <Dialog
      open={openDelete}
      PaperProps={{ elevation: 1 }}
      keepMounted={true}
      onClose={() => setOpenDelete(false)}
    >
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to delete this relationship?')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button
          onClick={() => setOpenDelete(false)}
          disabled={deleting}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button
          color="secondary"
          onClick={submitDelete}
          disabled={deleting}
        >
          {t_i18n('Delete')}
        </Button>
      </DialogActions>
    </Dialog>
  </>);
};

const StixCoreRelationshipHeader = createFragmentContainer(
  StixCoreRelationshipHeaderOverview,
  {
    stixCoreRelationship: graphql`
      fragment StixCoreRelationshipHeader_stixCoreRelationship on StixCoreRelationship {
        id
        relationship_type
        from {
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
          ... on Event {
            name
          }
          ... on Channel {
            name
          }
          ... on Narrative {
            name
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on ObservedData {
            name
          }
        }
        to {
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
          ... on Event {
            name
          }
          ... on Channel {
            name
          }
          ... on Narrative {
            name
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on ObservedData {
            name
          }
        }
      }
    `,
  },
);

export default StixCoreRelationshipHeader;
