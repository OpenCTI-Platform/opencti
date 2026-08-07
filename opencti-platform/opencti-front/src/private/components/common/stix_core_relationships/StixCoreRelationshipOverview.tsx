import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { ArrowRightAlt, EditOutlined, ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import { Stack, Tooltip, Typography, Box } from '@mui/material';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import Card from '../../../../components/common/card/Card';
import CardTitle from '../../../../components/common/card/CardTitle';
import Label from '../../../../components/common/label/Label';
import { useFormatter } from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemConfidence from '../../../../components/ItemConfidence';
import ItemCreators from '../../../../components/ItemCreators';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemStatus from '../../../../components/ItemStatus';
import { itemColor } from '../../../../utils/Colors';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { capitalizeFirstLetter, truncate } from '../../../../utils/String';
import StixCoreRelationshipExternalReferences from '../../analyses/external_references/StixCoreRelationshipExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectOrStixRelationshipLastContainers from '../containers/StixCoreObjectOrStixRelationshipLastContainers';
import { DraftChip } from '../draft/DraftChip';
import StixCoreObjectKillChainPhasesView from '../stix_core_objects/StixCoreObjectKillChainPhasesView';
import StixCoreRelationshipEdition, { stixCoreRelationshipEditionDeleteMutation } from './StixCoreRelationshipEdition';
import { stixCoreRelationshipEditionFocus } from './StixCoreRelationshipEditionOverview';
import StixCoreRelationshipInference from './StixCoreRelationshipInference';
import StixCoreRelationshipObjectLabelsView from './StixCoreRelationshipLabelsView';
import StixCoreRelationshipLatestHistory from './StixCoreRelationshipLatestHistory';
import StixCoreRelationshipSharing from './StixCoreRelationshipSharing';
import StixCoreRelationshipStixCoreRelationships from './StixCoreRelationshipStixCoreRelationships';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import SecurityCoverageInformation from '../../analyses/security_coverages/SecurityCoverageInformation';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { StixCoreRelationshipOverview_stixCoreRelationship$key } from './__generated__/StixCoreRelationshipOverview_stixCoreRelationship.graphql';
import { useComputeLink } from 'src/utils/hooks/useAppData';
import { Theme } from 'src/components/Theme';

const fragment = graphql`
      fragment StixCoreRelationshipOverview_stixCoreRelationship on StixCoreRelationship {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        entity_type
        parent_types
        relationship_type
        confidence
        created
        start_time
        stop_time
        description
        fromRole
        toRole
        created_at
        updated_at
        is_inferred
        coverage_information {
          coverage_name
          coverage_score
        }
        creators {
          id
          name
        }
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
        killChainPhases {
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
        }
        x_opencti_inferences {
          rule {
            id
            name
            description
          }
          explanation {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
              created_at
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
            ... on StixCoreRelationship {
              id
              relationship_type
              created_at
              start_time
              stop_time
              created
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreObject {
                  created_at
                }
                ... on StixCoreRelationship {
                  relationship_type
                  created_at
                  start_time
                  stop_time
                  created
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
                  objects(first: 1) {
                    edges {
                      node {
                        ... on StixCoreObject {
                          id
                          entity_type
                          parent_types
                          created_at
                          createdBy {
                            ... on Identity {
                              id
                              name
                              entity_type
                            }
                          }
                          objectMarking {
                            id
                            definition_type
                            definition
                            x_opencti_order
                            x_opencti_color
                          }
                        }
                        ... on AttackPattern {
                          name
                          description
                          x_mitre_id
                        }
                        ... on Campaign {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Note {
                          attribute_abstract
                        }
                        ... on ObservedData {
                          name
                          first_observed
                          last_observed
                        }
                        ... on Opinion {
                          opinion
                        }
                        ... on Report {
                          name
                          description
                          published
                        }
                        ... on Grouping {
                          name
                          description
                        }
                        ... on CourseOfAction {
                          name
                          description
                        }
                        ... on Individual {
                          name
                          description
                        }
                        ... on Organization {
                          name
                          description
                        }
                        ... on Sector {
                          name
                          description
                        }
                        ... on System {
                          name
                          description
                        }
                        ... on Indicator {
                          name
                          description
                          valid_from
                        }
                        ... on Infrastructure {
                          name
                          description
                        }
                        ... on IntrusionSet {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Position {
                          name
                          description
                        }
                        ... on City {
                          name
                          description
                        }
                        ... on AdministrativeArea {
                          name
                          description
                        }
                        ... on Country {
                          name
                          description
                        }
                        ... on Region {
                          name
                          description
                        }
                        ... on Malware {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on MalwareAnalysis {
                          result_name
                        }
                        ... on ThreatActor {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Tool {
                          name
                          description
                        }
                        ... on Vulnerability {
                          name
                          description
                        }
                        ... on Incident {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Event {
                          name
                          description
                          start_time
                          stop_time
                        }
                        ... on Channel {
                          name
                          description
                        }
                        ... on Narrative {
                          name
                          description
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
                          x_opencti_description
                        }
                      }
                    }
                  }
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
                  start_time
                  stop_time
                  created
                  from {
                    ... on BasicObject {
                      id
                      entity_type
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
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
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
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
                    ... on ObservedData {
                      name
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition_type
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
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
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              fromId
              fromType
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreObject {
                  created_at
                }
                ... on StixCoreRelationship {
                  created_at
                  relationship_type
                  start_time
                  stop_time
                  created
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
                  objects(first: 1) {
                    edges {
                      node {
                        ... on StixCoreObject {
                          id
                          entity_type
                          parent_types
                          created_at
                          createdBy {
                            ... on Identity {
                              id
                              name
                              entity_type
                            }
                          }
                          objectMarking {
                            id
                            definition
                            definition_type
                            x_opencti_order
                            x_opencti_color
                          }
                        }
                        ... on AttackPattern {
                          name
                          description
                          x_mitre_id
                        }
                        ... on Campaign {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Note {
                          attribute_abstract
                        }
                        ... on ObservedData {
                          name
                          first_observed
                          last_observed
                        }
                        ... on Opinion {
                          opinion
                        }
                        ... on Report {
                          name
                          description
                          published
                        }
                        ... on Grouping {
                          name
                          description
                        }
                        ... on CourseOfAction {
                          name
                          description
                        }
                        ... on Individual {
                          name
                          description
                        }
                        ... on Organization {
                          name
                          description
                        }
                        ... on Sector {
                          name
                          description
                        }
                        ... on System {
                          name
                          description
                        }
                        ... on Indicator {
                          name
                          description
                          valid_from
                        }
                        ... on Infrastructure {
                          name
                          description
                        }
                        ... on IntrusionSet {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Position {
                          name
                          description
                        }
                        ... on City {
                          name
                          description
                        }
                        ... on AdministrativeArea {
                          name
                          description
                        }
                        ... on Country {
                          name
                          description
                        }
                        ... on Region {
                          name
                          description
                        }
                        ... on Malware {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on MalwareAnalysis {
                          result_name
                        }
                        ... on ThreatActor {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Tool {
                          name
                          description
                        }
                        ... on Vulnerability {
                          name
                          description
                        }
                        ... on Incident {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Event {
                          name
                          description
                          start_time
                          stop_time
                        }
                        ... on Channel {
                          name
                          description
                        }
                        ... on Narrative {
                          name
                          description
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
                          x_opencti_description
                        }
                      }
                    }
                  }
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
                  start_time
                  stop_time
                  created
                  from {
                    ... on BasicObject {
                      id
                      entity_type
                      parent_types
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                      parent_types
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
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
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                definition_type
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
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
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                  to {
                    ... on BasicObject {
                      id
                      entity_type
                      parent_types
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                      parent_types
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
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
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                definition_type
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
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
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              toId
              toType
            }
            ... on StixSightingRelationship {
              id
              created_at
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreObject {
                  created_at
                }
                ... on StixCoreRelationship {
                  relationship_type
                  created_at
                  start_time
                  stop_time
                  created
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
                  objects(first: 1) {
                    edges {
                      node {
                        ... on StixCoreObject {
                          id
                          entity_type
                          parent_types
                          created_at
                          createdBy {
                            ... on Identity {
                              id
                              name
                              entity_type
                            }
                          }
                          objectMarking {
                            id
                            definition
                            definition_type
                            x_opencti_order
                            x_opencti_color
                          }
                        }
                        ... on AttackPattern {
                          name
                          description
                          x_mitre_id
                        }
                        ... on Campaign {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Note {
                          attribute_abstract
                        }
                        ... on ObservedData {
                          name
                          first_observed
                          last_observed
                        }
                        ... on Opinion {
                          opinion
                        }
                        ... on Report {
                          name
                          description
                          published
                        }
                        ... on Grouping {
                          name
                          description
                        }
                        ... on CourseOfAction {
                          name
                          description
                        }
                        ... on Individual {
                          name
                          description
                        }
                        ... on Organization {
                          name
                          description
                        }
                        ... on Sector {
                          name
                          description
                        }
                        ... on System {
                          name
                          description
                        }
                        ... on Indicator {
                          name
                          description
                          valid_from
                        }
                        ... on Infrastructure {
                          name
                          description
                        }
                        ... on IntrusionSet {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Position {
                          name
                          description
                        }
                        ... on City {
                          name
                          description
                        }
                        ... on AdministrativeArea {
                          name
                          description
                        }
                        ... on Country {
                          name
                          description
                        }
                        ... on Region {
                          name
                          description
                        }
                        ... on Malware {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on MalwareAnalysis {
                          result_name
                        }
                        ... on ThreatActor {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Tool {
                          name
                          description
                        }
                        ... on Vulnerability {
                          name
                          description
                        }
                        ... on Incident {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Event {
                          name
                          description
                          start_time
                          stop_time
                        }
                        ... on Channel {
                          name
                          description
                        }
                        ... on Narrative {
                          name
                          description
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
                          x_opencti_description
                        }
                      }
                    }
                  }
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
                  start_time
                  stop_time
                  created
                  from {
                    ... on BasicObject {
                      id
                      entity_type
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
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
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
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
                    ... on ObservedData {
                      name
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                definition_type
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
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
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              fromId
              fromType
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreObject {
                  created_at
                }
                ... on StixCoreRelationship {
                  created_at
                  relationship_type
                  start_time
                  stop_time
                  created
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
                  objects(first: 1) {
                    edges {
                      node {
                        ... on StixCoreObject {
                          id
                          entity_type
                          parent_types
                          created_at
                          createdBy {
                            ... on Identity {
                              id
                              name
                              entity_type
                            }
                          }
                          objectMarking {
                            id
                            definition
                            definition_type
                            x_opencti_order
                            x_opencti_color
                          }
                        }
                        ... on AttackPattern {
                          name
                          description
                          x_mitre_id
                        }
                        ... on Campaign {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Note {
                          attribute_abstract
                        }
                        ... on ObservedData {
                          name
                          first_observed
                          last_observed
                        }
                        ... on Opinion {
                          opinion
                        }
                        ... on Report {
                          name
                          description
                          published
                        }
                        ... on Grouping {
                          name
                          description
                        }
                        ... on CourseOfAction {
                          name
                          description
                        }
                        ... on Individual {
                          name
                          description
                        }
                        ... on Organization {
                          name
                          description
                        }
                        ... on Sector {
                          name
                          description
                        }
                        ... on System {
                          name
                          description
                        }
                        ... on Indicator {
                          name
                          description
                          valid_from
                        }
                        ... on Infrastructure {
                          name
                          description
                        }
                        ... on IntrusionSet {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Position {
                          name
                          description
                        }
                        ... on City {
                          name
                          description
                        }
                        ... on AdministrativeArea {
                          name
                          description
                        }
                        ... on Country {
                          name
                          description
                        }
                        ... on Region {
                          name
                          description
                        }
                        ... on Malware {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on MalwareAnalysis {
                          result_name
                        }
                        ... on ThreatActor {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Tool {
                          name
                          description
                        }
                        ... on Vulnerability {
                          name
                          description
                        }
                        ... on Incident {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Event {
                          name
                          description
                          start_time
                          stop_time
                        }
                        ... on Channel {
                          name
                          description
                        }
                        ... on Narrative {
                          name
                          description
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
                          x_opencti_description
                        }
                      }
                    }
                  }
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
                  start_time
                  stop_time
                  created
                  from {
                    ... on BasicObject {
                      id
                      entity_type
                      parent_types
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                      parent_types
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
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
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                definition_type
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
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
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                  to {
                    ... on BasicObject {
                      id
                      entity_type
                      parent_types
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                      parent_types
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
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
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                definition_type
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
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
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              toId
              toType
            }
          }
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          id
          definition
          definition_type
          x_opencti_order
          x_opencti_color
        }
        objectLabel {
          id
          value
          color
        }
        from {
          ... on BasicObject {
            id
            entity_type
            parent_types
          }
          ... on BasicRelationship {
            id
            entity_type
            parent_types
          }
          ... on StixCoreObject {
            draftVersion {
              draft_id
              draft_operation
            }
            created_at
          }
          ... on StixCoreRelationship {
            draftVersion {
              draft_id
              draft_operation
            }
            created_at
            start_time
            stop_time
            created
          }
          ... on StixCyberObservable {
            observable_value
            representative {
              main
            }
          }
          ... on SecurityCoverageResult {
            resultOf {
              id
            }
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
          ... on StixDomainObject {
            representative {
              main
            }
          }
          ... on ObservedData {
            name
            objects(first: 1) {
              edges {
                node {
                  ... on StixCoreObject {
                    id
                    entity_type
                    parent_types
                    created_at
                    createdBy {
                      ... on Identity {
                        id
                        name
                        entity_type
                      }
                    }
                    objectMarking {
                      id
                      definition
                      definition_type
                      x_opencti_order
                      x_opencti_color
                    }
                  }
                  ... on AttackPattern {
                    name
                    description
                    x_mitre_id
                  }
                  ... on Campaign {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Note {
                    attribute_abstract
                  }
                  ... on ObservedData {
                    name
                    first_observed
                    last_observed
                  }
                  ... on Opinion {
                    opinion
                  }
                  ... on Report {
                    name
                    description
                    published
                  }
                  ... on Grouping {
                    name
                    description
                  }
                  ... on CourseOfAction {
                    name
                    description
                  }
                  ... on Individual {
                    name
                    description
                  }
                  ... on Organization {
                    name
                    description
                  }
                  ... on Sector {
                    name
                    description
                  }
                  ... on System {
                    name
                    description
                  }
                  ... on Indicator {
                    name
                    description
                    valid_from
                  }
                  ... on Infrastructure {
                    name
                    description
                  }
                  ... on IntrusionSet {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Position {
                    name
                    description
                  }
                  ... on City {
                    name
                    description
                  }
                  ... on AdministrativeArea {
                    name
                  }
                  ... on Country {
                    name
                    description
                  }
                  ... on Region {
                    name
                    description
                  }
                  ... on Malware {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on MalwareAnalysis {
                    result_name
                  }
                  ... on ThreatActor {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Tool {
                    name
                    description
                  }
                  ... on Vulnerability {
                    name
                    description
                  }
                  ... on Incident {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Event {
                    name
                    description
                    start_time
                    stop_time
                  }
                  ... on Channel {
                    name
                    description
                  }
                  ... on Narrative {
                    name
                    description
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
                    x_opencti_description
                  }
                }
              }
            }
          }
          ... on StixCoreRelationship {
            id
            entity_type
            relationship_type
            start_time
            stop_time
            created
            from {
              ... on BasicObject {
                id
                entity_type
              }
              ... on BasicRelationship {
                id
                entity_type
              }
              ... on StixCoreObject {
                created_at
              }
              ... on StixCoreRelationship {
                created_at
                start_time
                stop_time
                created
              }
              ... on StixCyberObservable {
                observable_value
                representative {
                  main
                }
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
              ... on StixCoreObject {
                created_at
              }
              ... on StixCoreRelationship {
                created_at
                start_time
                stop_time
                created
              }
              ... on StixCyberObservable {
                observable_value
                representative {
                  main
                }
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
            }
          }
        }
        fromId
        fromType
        to {
          ... on BasicObject {
            id
            entity_type
            parent_types
          }
          ... on BasicRelationship {
            id
            entity_type
            parent_types
          }
          ... on StixCoreObject {
            draftVersion {
              draft_id
              draft_operation
            }
            created_at
          }
          ... on StixCoreRelationship {
            draftVersion {
              draft_id
              draft_operation
            }
            created_at
            start_time
            stop_time
            created
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
            objects(first: 1) {
              edges {
                node {
                  ... on StixCoreObject {
                    id
                    entity_type
                    parent_types
                    created_at
                    createdBy {
                      ... on Identity {
                        id
                        name
                        entity_type
                      }
                    }
                    objectMarking {
                      id
                      definition
                      definition_type
                      x_opencti_order
                      x_opencti_color
                    }
                  }
                  ... on AttackPattern {
                    name
                    description
                    x_mitre_id
                  }
                  ... on Campaign {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Note {
                    attribute_abstract
                  }
                  ... on ObservedData {
                    name
                    first_observed
                    last_observed
                  }
                  ... on Opinion {
                    opinion
                  }
                  ... on Report {
                    name
                    description
                    published
                  }
                  ... on Grouping {
                    name
                    description
                  }
                  ... on CourseOfAction {
                    name
                    description
                  }
                  ... on Individual {
                    name
                    description
                  }
                  ... on Organization {
                    name
                    description
                  }
                  ... on Sector {
                    name
                    description
                  }
                  ... on System {
                    name
                    description
                  }
                  ... on Indicator {
                    name
                    description
                    valid_from
                  }
                  ... on Infrastructure {
                    name
                    description
                  }
                  ... on IntrusionSet {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Position {
                    name
                    description
                  }
                  ... on City {
                    name
                    description
                  }
                  ... on AdministrativeArea {
                    name
                    description
                  }
                  ... on Country {
                    name
                    description
                  }
                  ... on Region {
                    name
                    description
                  }
                  ... on Malware {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on MalwareAnalysis {
                    result_name
                  }
                  ... on ThreatActor {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Tool {
                    name
                    description
                  }
                  ... on Vulnerability {
                    name
                    description
                  }
                  ... on Incident {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Event {
                    name
                    start_time
                    stop_time
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
                    x_opencti_description
                  }
                }
              }
            }
          }
          ... on StixCoreRelationship {
            id
            entity_type
            relationship_type
            start_time
            stop_time
            created
            from {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on BasicRelationship {
                id
                entity_type
                parent_types
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
            }
            to {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on BasicRelationship {
                id
                entity_type
                parent_types
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
            }
          }
        }
        toId
        toType
      }
    `;

const useStyles = makeStyles((theme: Theme) => ({
  container: {
    margin: 0,
    position: 'relative',
  },
  gridContainer: {
    marginBottom: 20,
  },
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
    borderRadius: 8,
  },
  itemHeader: {
    padding: '10px 0 10px 0',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: theme.palette.text.primary,
    fontSize: 11,
  },
  content: {
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '0 10px 0 10px',
    height: 40,
    maxHeight: 40,
    color: theme.palette.text.primary,
    textAlign: 'center',
    wordBreak: 'break-word',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  middle: {
    margin: '0 auto',
    paddingTop: 20,
    width: 200,
    textAlign: 'center',
    color: theme.palette.text.primary,
  },
  buttonExpand: {
    position: 'absolute',
    left: 0,
    bottom: 0,
    width: '100%',
    height: 25,
    color: theme.palette.primary.main,
    backgroundColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .2)'
          : 'rgba(0, 0, 0, .2)',
    },
  },
}));

const TRUNCATE_CHARS_COUNT = 40;

interface StixCoreRelationshipOverviewProps {
  data: StixCoreRelationshipOverview_stixCoreRelationship$key;
}

const StixCoreRelationshipOverview = ({
  data,
}: StixCoreRelationshipOverviewProps) => {
  const [openEdit, setOpenEdit] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [openDelete, setOpenDelete] = useState(false);
  const [commitFocusMutation] = useApiMutation(stixCoreRelationshipEditionFocus);
  const [commitDeleteMutation] = useApiMutation(stixCoreRelationshipEditionDeleteMutation);
  const navigate = useNavigate();
  const location = useLocation();
  const { t_i18n, nsdt, fldt } = useFormatter();
  const classes = useStyles();
  const stixCoreRelationship = useFragment(fragment, data);
  const computeLink = useComputeLink();

  const handleCloseEdition = () => {
    commitFocusMutation({
      variables: {
        id: stixCoreRelationship.id,
        input: { focusOn: '' },
      },
    });
    setOpenEdit(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commitDeleteMutation({
      variables: {
        id: stixCoreRelationship.id,
      },
      onCompleted: () => {
        handleCloseEdition();
        navigate(
          location.pathname.replace(`/relations/${stixCoreRelationship.id}`, ''),
        );
      },
    });
  };

  const { from, to, relationship_type, coverage_information } = stixCoreRelationship;
  const fromRestricted = from === null;

  const linkFrom = from ? computeLink(from) : '';
  const toRestricted = to === null;

  const linkTo = to ? computeLink(to) : '';

  const expandable = stixCoreRelationship.x_opencti_inferences
    && stixCoreRelationship.x_opencti_inferences.length > 1;

  const fromText = getMainRepresentative(from) !== 'Unknown'
    ? getMainRepresentative(from)
    : t_i18n(`relationship_${from?.entity_type}`);

  const toText = getMainRepresentative(to) !== 'Unknown'
    ? getMainRepresentative(to)
    : t_i18n(`relationship_${to?.entity_type}`);

  return (
    <div className={classes.container}>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={6}>
          <Card
            title={<>{t_i18n('Relationship')}{stixCoreRelationship.draftVersion && (<DraftChip />)}</>}
            action={!stixCoreRelationship.is_inferred && (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <>
                  <IconButton
                    aria-label={t_i18n('Edit')}
                    color="primary"
                    onClick={() => setOpenEdit(true)}
                    size="small"
                  >
                    <EditOutlined fontSize="small" />
                  </IconButton>
                  <StixCoreRelationshipEdition
                    open={openEdit}
                    stixCoreRelationshipId={stixCoreRelationship.id}
                    handleClose={handleCloseEdition}
                    handleDelete={() => setOpenDelete(true)}
                    noStoreUpdate={false}
                  />
                </>
              </Security>
            )}
          >
            <Link to={linkFrom ?? ''}>
              <div
                className={classes.item}
                style={{
                  border: `1px solid ${itemColor(
                    !fromRestricted ? from?.entity_type : 'Restricted',
                  )}`,
                  top: 20,
                  left: 20,
                }}
              >
                <div
                  className={classes.itemHeader}
                  style={{
                    borderBottom: `1px solid ${itemColor(
                      !fromRestricted ? from?.entity_type : 'Restricted',
                    )}`,
                  }}
                >
                  <div className={classes.icon}>
                    <ItemIcon
                      type={!fromRestricted ? from?.entity_type : 'Restricted'}
                      color={itemColor(
                        !fromRestricted ? from?.entity_type : 'Restricted',
                      )}
                      size="small"
                    />
                  </div>
                  <div className={classes.type}>
                    { }
                    {!fromRestricted
                      ? from?.relationship_type
                        ? t_i18n('Relationship')
                        : t_i18n(`entity_${from?.entity_type}`)
                      : t_i18n('Restricted')}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    <Tooltip title={fromText}>
                      <>
                        {!fromRestricted
                          ? truncate(fromText, TRUNCATE_CHARS_COUNT)
                          : t_i18n('Restricted')}
                      </>
                    </Tooltip>
                    {!fromRestricted && from?.draftVersion && (<DraftChip />)}
                  </span>
                </div>
              </div>
            </Link>
            <div className={classes.middle}>
              <ArrowRightAlt fontSize="large" />
              <Typography sx={{ fontSize: '14px', fontWeight: 400 }}>
                {capitalizeFirstLetter(t_i18n(`relationship_${stixCoreRelationship.relationship_type}`))}
              </Typography>
            </div>
            <Link to={linkTo ?? ''}>
              <div
                className={classes.item}
                style={{
                  border: `1px solid ${itemColor(
                    !toRestricted ? to?.entity_type : 'Restricted',
                  )}`,
                  top: 20,
                  right: 20,
                }}
              >
                <div
                  className={classes.itemHeader}
                  style={{
                    borderBottom: `1px solid ${itemColor(
                      !toRestricted ? to?.entity_type : 'Restricted',
                    )}`,
                  }}
                >
                  <div className={classes.icon}>
                    <ItemIcon
                      type={!toRestricted ? to?.entity_type : 'Unknown'}
                      color={itemColor(
                        !toRestricted ? to?.entity_type : 'Restricted',
                      )}
                      size="small"
                    />
                  </div>
                  <div className={classes.type}>
                    {
                      !toRestricted
                        ? to?.relationship_type
                          ? t_i18n('Relationship')
                          : t_i18n(`entity_${to?.entity_type}`)
                        : t_i18n('Restricted')
                    }
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    <Tooltip title={toText}>
                      <>
                        {!toRestricted
                          ? truncate(toText, TRUNCATE_CHARS_COUNT)
                          : t_i18n('Restricted')}
                      </>
                    </Tooltip>
                    {!toRestricted && to?.draftVersion && (<DraftChip />)}
                  </span>
                </div>
              </div>
            </Link>
            <Divider style={{ marginTop: 30, marginBottom: 15 }} />
            <Stack gap={2}>
              <div>
                <Label>
                  {t_i18n('Description')}
                </Label>
                <ExpandableMarkdown
                  source={stixCoreRelationship.x_opencti_inferences !== null
                    ? t_i18n('Inferred knowledge')
                    : stixCoreRelationship.description
                  }
                  limit={400}
                />
              </div>
              <Divider />

              <Grid container={true} spacing={2}>
                <Grid item xs={6}>
                  <Label>
                    {t_i18n('Marking')}
                  </Label>
                  <ItemMarkings markingDefinitions={stixCoreRelationship.objectMarking ?? []} />
                  <Label
                    sx={{ marginTop: 2 }}
                  >
                    {t_i18n('Start time')}
                  </Label>
                  {nsdt(stixCoreRelationship.start_time)}
                  <Label sx={{ marginTop: 2 }}>
                    {t_i18n('Stop time')}
                  </Label>
                  {nsdt(stixCoreRelationship.stop_time)}
                </Grid>
                <Grid item xs={6}>
                  {relationship_type === 'has-covered'
                    && (
                      <Box sx={{ marginBottom: 2 }}>
                        <SecurityCoverageInformation coverage_information={coverage_information} />
                      </Box>
                    )
                  }
                  <StixCoreRelationshipSharing
                    elementId={stixCoreRelationship.id}
                  />
                  <StixCoreObjectKillChainPhasesView
                    killChainPhases={stixCoreRelationship.killChainPhases}
                    displayIcon
                  />
                </Grid>
              </Grid>
            </Stack>
          </Card>
        </Grid>
        <Grid item xs={6}>
          <Card title={t_i18n('Details')}>
            <Grid container={true} spacing={2}>
              <Grid item xs={6}>
                <Label>
                  {t_i18n('Confidence level')}
                </Label>
                <ItemConfidence
                  confidence={stixCoreRelationship.confidence}
                  entityType="stix-core-relationship"
                />
                {stixCoreRelationship.x_opencti_inferences === null && (
                  <div>
                    <Label
                      sx={{ marginTop: 2 }}
                    >
                      {t_i18n('Author')}
                    </Label>
                    <ItemAuthor
                      createdBy={R.propOr(
                        null,
                        'createdBy',
                        stixCoreRelationship,
                      )}
                    />
                  </div>
                )}
                <Label
                  sx={{ marginTop: 2 }}
                >
                  {t_i18n('Original creation date')}
                </Label>
                {nsdt(stixCoreRelationship.created)}
                <Label
                  sx={{ marginTop: 2 }}
                >
                  {t_i18n('Modification date')}
                </Label>
                {nsdt(stixCoreRelationship.updated_at)}
              </Grid>
              <Grid item xs={6}>
                <Label>
                  {t_i18n('Processing status')}
                </Label>
                <ItemStatus
                  status={stixCoreRelationship.status}
                  disabled={!stixCoreRelationship.workflowEnabled}
                />
                <StixCoreRelationshipObjectLabelsView
                  labels={stixCoreRelationship.objectLabel}
                  id={stixCoreRelationship.id}
                  sx={{ marginTop: 2 }}
                />
                <Label
                  sx={{ marginTop: 2 }}
                >
                  {t_i18n('Platform creation date')}
                </Label>
                {fldt(stixCoreRelationship.created_at)}
                <Label
                  sx={{ marginTop: 2 }}
                >
                  {t_i18n('Creators')}
                </Label>
                <ItemCreators
                  creators={stixCoreRelationship.creators ?? []}
                />
              </Grid>
            </Grid>
          </Card>
        </Grid>
        {stixCoreRelationship.x_opencti_inferences == null && (
          <>
            <Grid item xs={6}>
              <StixCoreRelationshipStixCoreRelationships
                entityId={stixCoreRelationship.id}
              />
            </Grid>
            <Grid item xs={6}>
              <StixCoreObjectOrStixRelationshipLastContainers
                stixCoreObjectOrStixRelationshipId={stixCoreRelationship.id}
              />
            </Grid>
            <Grid item xs={6}>
              <StixCoreRelationshipExternalReferences
                stixCoreRelationshipId={stixCoreRelationship.id}
              />
            </Grid>
            <Grid item xs={6}>
              <StixCoreRelationshipLatestHistory
                stixCoreRelationshipId={stixCoreRelationship.id}
              />
            </Grid>
            <Grid item xs={12}>
              <StixCoreObjectOrStixCoreRelationshipNotes
                stixCoreObjectOrStixCoreRelationshipId={stixCoreRelationship.id}
                isRelationship={true}
                defaultMarkings={stixCoreRelationship.objectMarking ?? []}
              />
            </Grid>
          </>
        )}
      </Grid>
      <div>
        {stixCoreRelationship.x_opencti_inferences !== null && (
          <div style={{ margin: '50px 0 0 0' }}>
            <CardTitle>
              {t_i18n('Inference explanation')} (
              {stixCoreRelationship.x_opencti_inferences?.length})
            </CardTitle>
            {R.take(
              expanded ? 200 : 1,
              stixCoreRelationship.x_opencti_inferences ?? [],
            ).map((inference) => (
              <StixCoreRelationshipInference
                key={inference?.rule.id}
                inference={inference}
                stixRelationship={stixCoreRelationship}
              />
            ))}
            {expandable && (
              <IconButton
                aria-label={expanded ? t_i18n('Collapse') : t_i18n('Expand')}
                variant="tertiary"
                size="small"
                onClick={() => setExpanded(true)}
                classes={{ root: classes.buttonExpand }}
              >
                {expanded ? (
                  <ExpandLessOutlined />
                ) : (
                  <ExpandMoreOutlined />
                )}
              </IconButton>
            )}
          </div>
        )}
      </div>
      <Dialog
        open={openDelete}
        onClose={() => setOpenDelete(false)}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this relationship?')}
        </DialogContentText>
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
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default StixCoreRelationshipOverview;
