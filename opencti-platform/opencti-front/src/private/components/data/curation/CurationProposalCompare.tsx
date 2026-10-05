import { ReactNode } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import Tag from '@common/tag/Tag';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { resolveLink } from '../../../../utils/Entity';
import { truncate } from '../../../../utils/String';
import type { Theme } from '../../../../components/Theme';
import { CurationProposalCompare_proposal$data, CurationProposalCompare_proposal$key } from './__generated__/CurationProposalCompare_proposal.graphql';

export const compareFragment = graphql`
  fragment CurationProposalCompare_proposal on CurationProposal {
    id
    subject_ids
    subject_types
    subject_names
    target_id
    restricted_subjects_count
    subjects {
      ... on BasicObject {
        id
        entity_type
      }
      ... on BasicRelationship {
        id
        entity_type
      }
      ... on StixCoreObject {
        representative {
          main
        }
        created_at
        updated_at
        createdBy {
          name
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        objectLabel {
          id
          value
          color
        }
        numberOfConnectedElement
        toStix
      }
      ... on StixDomainObject {
        confidence
        created
        modified
        revoked
      }
      ... on StixCoreRelationship {
        relationship_type
        description
        from {
          ... on StixCoreObject {
            representative {
              main
            }
          }
        }
        to {
          ... on StixCoreObject {
            representative {
              main
            }
          }
        }
      }
    }
  }
`;

interface StixDocument {
  name?: string;
  description?: string;
  aliases?: string[];
  x_opencti_aliases?: string[];
  external_references?: unknown[];
  first_seen?: string;
  last_seen?: string;
}

const parseStix = (value: string | null | undefined): StixDocument => {
  if (!value) return {};
  try {
    return JSON.parse(value) as StixDocument;
  } catch {
    return {};
  }
};

/** What a merge or an alias addition moves to the surviving entity, for the approval of the change. */
export interface CurationMergePreview {
  /** Subjects merged into, or named as aliases of, the survivor. */
  count: number;
  relationships: number;
  aliases: string[];
  externalReferences: number;
}

/**
 * An alias proposal adds the names of its payload (*proposedAliases*), never the names of other subjects: it often has
 * a single subject. A merge moves the names of the other subjects.
 */
export const buildMergePreview = (
  proposal: CurationProposalCompare_proposal$data,
  survivorId: string | null,
  proposedAliases: string[] | null = null,
): CurationMergePreview | null => {
  if (!survivorId) return null;
  const subjects = proposal.subjects.filter((subject) => !!subject?.id);
  const survivor = subjects.find((subject) => subject.id === survivorId);
  if (!survivor) return null;
  const others = subjects.filter((subject) => subject.id !== survivorId);
  const namesOf = (subject: (typeof subjects)[number]) => {
    const document = parseStix(subject.toStix);
    return [subject.representative?.main ?? document.name, ...(document.aliases ?? document.x_opencti_aliases ?? [])].filter((name): name is string => !!name);
  };
  const known = new Set(namesOf(survivor).map((name) => name.toLowerCase()));
  const aliases: string[] = [];
  (proposedAliases ?? others.flatMap(namesOf)).forEach((name) => {
    if (!known.has(name.toLowerCase())) {
      known.add(name.toLowerCase());
      aliases.push(name);
    }
  });
  return {
    count: Math.max(0, proposal.subject_ids.length - 1),
    relationships: others.reduce((total, subject) => total + (subject.numberOfConnectedElement ?? 0), 0),
    aliases,
    externalReferences: others.reduce((total, subject) => total + (parseStix(subject.toStix).external_references ?? []).length, 0),
  };
};

interface CurationProposalCompareProps {
  data: CurationProposalCompare_proposal$key;
  survivorId: string | null;
  onSelectSurvivor?: (id: string) => void;
  /** Subjects offered for selection; every subject when omitted. */
  selectableIds?: string[];
  selectedLabel?: string;
}

const CurationProposalCompare = ({ data, survivorId, onSelectSurvivor, selectableIds, selectedLabel }: CurationProposalCompareProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, n } = useFormatter();
  const proposal = useFragment(compareFragment, data);
  type Subject = (typeof proposal.subjects)[number];
  const subjects = proposal.subjects.filter((subject): subject is Subject & { id: string; entity_type: string } => !!subject?.id && !!subject.entity_type);
  const documents = subjects.map((subject) => parseStix(subject.toStix));
  const highlight = (id: string) => (survivorId === id ? { backgroundColor: theme.palette.background.accent } : {});

  const rows: Array<{ label: string; render: (index: number) => ReactNode }> = [
    { label: t_i18n('Entity type'), render: (index) => t_i18n(`entity_${subjects[index].entity_type}`) },
    {
      label: t_i18n('Name'),
      render: (index) => {
        const subject = subjects[index];
        const name = subject.representative?.main ?? documents[index].name ?? proposal.subject_names[index];
        const link = resolveLink(subject.entity_type);
        return link ? <Link to={`${link}/${subject.id}`}>{name}</Link> : name;
      },
    },
    {
      label: t_i18n('Aliases'),
      render: (index) => {
        const aliases = documents[index].aliases ?? documents[index].x_opencti_aliases ?? [];
        return aliases.length === 0 ? '-' : (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {aliases.slice(0, 15).map((alias) => <Tag key={alias} label={alias} />)}
            {aliases.length > 15 && <span>+{aliases.length - 15}</span>}
          </Box>
        );
      },
    },
    {
      label: t_i18n('Description'),
      render: (index) => {
        const description = documents[index].description ?? subjects[index].description;
        return description ? <span title={description}>{truncate(description, 280)}</span> : '-';
      },
    },
    {
      label: t_i18n('Relationship'),
      render: (index) => {
        const subject = subjects[index];
        if (!subject.relationship_type) return '-';
        const restricted = t_i18n('Restricted');
        return `${subject.from?.representative?.main ?? restricted} ${t_i18n(`relationship_${subject.relationship_type}`)} ${subject.to?.representative?.main ?? restricted}`;
      },
    },
    { label: t_i18n('Author'), render: (index) => subjects[index].createdBy?.name ?? '-' },
    {
      label: t_i18n('Markings'),
      render: (index) => <ItemMarkings markingDefinitions={subjects[index].objectMarking ?? []} limit={3} />,
    },
    {
      label: t_i18n('Labels'),
      render: (index) => {
        const objectLabels = subjects[index].objectLabel ?? [];
        return objectLabels.length === 0 ? '-' : (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {objectLabels.map((label) => <Tag key={label.id} label={label.value} color={label.color} />)}
          </Box>
        );
      },
    },
    { label: t_i18n('Confidence level'), render: (index) => subjects[index].confidence ?? '-' },
    {
      label: t_i18n('First seen / last seen'),
      render: (index) => {
        const { first_seen: firstSeen, last_seen: lastSeen } = documents[index];
        return firstSeen || lastSeen ? `${firstSeen ? fldt(firstSeen) : '-'} / ${lastSeen ? fldt(lastSeen) : '-'}` : '-';
      },
    },
    { label: t_i18n('Original creation date'), render: (index) => (subjects[index].created ? fldt(subjects[index].created) : '-') },
    { label: t_i18n('Modification date'), render: (index) => (subjects[index].modified ? fldt(subjects[index].modified) : '-') },
    { label: t_i18n('Platform creation date'), render: (index) => (subjects[index].created_at ? fldt(subjects[index].created_at) : '-') },
    {
      label: t_i18n('Connected elements'),
      render: (index) => (subjects[index].numberOfConnectedElement !== undefined && subjects[index].numberOfConnectedElement !== null
        ? n(subjects[index].numberOfConnectedElement)
        : '-'),
    },
    { label: t_i18n('Revoked'), render: (index) => (subjects[index].revoked ? t_i18n('Yes') : t_i18n('No')) },
  ];

  return (
    <Card title={t_i18n('Side-by-side comparison')} padding="none">
      {proposal.restricted_subjects_count > 0 && (
        <Typography variant="body2" sx={{ paddingX: 3, paddingTop: 2 }} color="warning.main">
          {t_i18n('{count, plural, one {# subject is restricted: it is outside of your access and is not displayed.} other {# subjects are restricted: they are outside of your access and are not displayed.}}', { values: { count: proposal.restricted_subjects_count } })}
        </Typography>
      )}
      <Box sx={{ overflowX: 'auto' }}>
        <Table size="small" aria-label={t_i18n('Side-by-side comparison')} data-testid="curation-compare-table">
          <TableHead>
            <TableRow>
              <TableCell sx={{ width: 180 }} />
              {subjects.map((subject) => (
                <TableCell key={subject.id} sx={highlight(subject.id)}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                    <ItemIcon type={subject.entity_type} size="small" />
                    <strong>{subject.representative?.main ?? subject.id}</strong>
                    {survivorId === subject.id && <Tag label={selectedLabel ?? t_i18n('Survivor')} color={theme.palette.success.main} />}
                    {onSelectSurvivor && survivorId !== subject.id && (!selectableIds || selectableIds.includes(subject.id)) && (
                      <Button size="small" variant="tertiary" onClick={() => onSelectSurvivor(subject.id)}>
                        {t_i18n('Keep this one')}
                      </Button>
                    )}
                  </Box>
                </TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.label}>
                <TableCell component="th" scope="row" sx={{ color: theme.palette.text.light, verticalAlign: 'top' }}>
                  {row.label}
                </TableCell>
                {subjects.map((subject, index) => (
                  <TableCell key={subject.id} sx={{ ...highlight(subject.id), verticalAlign: 'top' }}>
                    {row.render(index)}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>
    </Card>
  );
};

export default CurationProposalCompare;
