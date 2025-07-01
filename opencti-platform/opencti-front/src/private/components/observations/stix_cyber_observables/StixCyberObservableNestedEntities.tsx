import React, { CSSProperties, useState } from 'react';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import StixNestedRefRelationCreationFromEntity from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableNestedEntitiesLines, { stixCyberObservableNestedEntitiesLinesQuery } from './StixCyberObservableNestedEntitiesLines';
import { useFormatter } from '../../../../components/i18n';

interface StixCyberObservableNestedEntitiesProps {
  entityId: string;
  entityType: string;
  variant?: 'inLine' | undefined;
}

const inlineStylesHeaders: Record<string, CSSProperties> = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  relationship_type: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  entity_type: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  name: {
    float: 'left',
    width: '22%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  creator: {
    float: 'left',
    width: '12%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  start_time: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  stop_time: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
};

const StixCyberObservableNestedEntities: React.FC<StixCyberObservableNestedEntitiesProps> = ({
  entityId,
  entityType,
  variant,
}) => {
  const { t_i18n } = useFormatter();
  const [sortBy, setSortBy] = useState<string | null>(null);
  const [orderAsc, setOrderAsc] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const handleSort = (field: string, isAsc: boolean) => {
    setSortBy(field);
    setOrderAsc(isAsc);
  };

  const handleSearch = (value: string) => {
    setSearchTerm(value);
  };

  const SortHeader = (field: string, label: string, isSortable: boolean) => {
    const sortComponent = orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field as keyof typeof inlineStylesHeaders]}
          onClick={() => handleSort(field, !orderAsc)}
        >
          <span>{t_i18n(label)}</span>
          {sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field as keyof typeof inlineStylesHeaders]}>
        <span>{t_i18n(label)}</span>
      </div>
    );
  };

  const getTargetStixCoreObjectTypes = () => {
    if (entityType === 'Network-Traffic') {
      return ['IPv4-Addr', 'IPv6-Addr', 'Domain-Name', 'Mac-Addr'];
    }
    return undefined;
  };

  const isInLine = variant === 'inLine';
  const paginationOptions = {
    fromOrToId: entityId,
    search: searchTerm,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  };
  const targetStixCoreObjectTypes = getTargetStixCoreObjectTypes();

  return (
    <div
      style={
        isInLine
          ? {
            height: 'auto',
            marginTop: 20,
            paddingBlock: 10,
          }
          : {
            height: '100%',
            marginTop: 0,
            paddingBlock: 0,
          }
      }
    >
      <Typography
        variant={isInLine ? 'h3' : 'h4'}
        gutterBottom={true}
        style={{ float: 'left' }}
      >
        {t_i18n('Nested objects')}
      </Typography>
      <Security
        needs={[KNOWLEDGE_KNUPDATE]}
        placeholder={<div style={{ height: 29 }}/>}
      >
        <StixNestedRefRelationCreationFromEntity
          paginationOptions={paginationOptions}
          entityId={entityId}
          variant="inLine"
          entityType={entityType}
          targetStixCoreObjectTypes={targetStixCoreObjectTypes}
        />
      </Security>
      {!isInLine && (
        <>
          <div style={{ float: 'right', marginTop: -10 }}>
            <SearchInput
              variant="thin"
              onSubmit={handleSearch}
              keyword={searchTerm}
            />
          </div>
          <div className="clearfix"/>
        </>
      )}
      <Paper
        style={{
          margin: 0,
          padding: isInLine ? 0 : 15,
          borderRadius: 4,
        }}
        elevation={0}
        variant={isInLine ? undefined : 'outlined'}
      >
        <List style={{ marginTop: isInLine ? 0 : -10 }}>
          <ListItem
            style={{
              paddingLeft: 10,
              paddingTop: 0,
              textTransform: 'uppercase',
            }}
            divider={false}
            secondaryAction={<> &nbsp; </>}
          >
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                &nbsp;
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {SortHeader('relationship_type', 'Attribute', true)}
                  {SortHeader('entity_type', 'Entity type', false)}
                  {SortHeader('name', 'Name', false)}
                  {SortHeader('creator', 'Creator', false)}
                  {SortHeader('start_time', 'First obs.', true)}
                  {SortHeader('stop_time', 'Last obs.', true)}
                </div>
              }
            />
          </ListItem>
          <QueryRenderer
            query={stixCyberObservableNestedEntitiesLinesQuery}
            variables={{ count: 200, ...paginationOptions }}
            render={({ props }: { props: unknown }) => (
              <StixCyberObservableNestedEntitiesLines
                stixCyberObservableId={entityId}
                paginationOptions={paginationOptions}
                data={props}
              />
            )}
          />
        </List>
      </Paper>
    </div>
  );
};

export default StixCyberObservableNestedEntities;
