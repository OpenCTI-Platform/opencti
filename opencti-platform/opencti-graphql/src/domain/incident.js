import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  refetchEntityById,
  graknNow,
  monthFormat,
  notify,
  paginate,
  prepareDate,
  timeSeries,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';

export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'incident', args));
};

export const incidentsTimeSeries = args => {
  return timeSeries('match $i isa Incident', args);
};

export const findByEntity = args => {
  return paginate(
    `match $x isa Incident;
    $rel($x, $to) isa stix_relation;
    $to has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
};

export const incidentsTimeSeriesByEntity = args => {
  return timeSeries(
    `match $x isa Incident; 
    $rel($x, $to) isa stix_relation; 
    $to has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
};

export const findById = incidentId => refetchEntityById(incidentId);

export const addIncident = async (user, incident) => {
  const incidentId = await executeWrite(async wTx => {
    const internalId = incident.internal_id_key
      ? escapeString(incident.internal_id_key)
      : uuid();
    const now = graknNow();
    const query = `insert $incident isa Incident,
    has internal_id_key "${internalId}",
    has entity_type "incident",
    has stix_id_key "${
      incident.stix_id_key
        ? escapeString(incident.stix_id_key)
        : `x-opencti-incident--${uuid()}`
    }",
    has stix_label "",
    ${
      incident.alias
        ? `${join(
            ' ',
            map(
              val => `has alias "${escapeString(val)}",`,
              tail(incident.alias)
            )
          )} has alias "${escapeString(head(incident.alias))}",`
        : 'has alias "",'
    }
    has name "${escapeString(incident.name)}",
    has description "${escapeString(incident.description)}",
    has first_seen ${
      incident.first_seen ? prepareDate(incident.first_seen) : now
    },
    has first_seen_day "${
      incident.first_seen ? dayFormat(incident.first_seen) : dayFormat(now)
    }",
    has first_seen_month "${
      incident.first_seen ? monthFormat(incident.first_seen) : monthFormat(now)
    }",
    has first_seen_year "${
      incident.first_seen ? yearFormat(incident.first_seen) : yearFormat(now)
    }",
    has last_seen ${incident.last_seen ? prepareDate(incident.last_seen) : now},
    has last_seen_day "${
      incident.last_seen ? dayFormat(incident.last_seen) : dayFormat(now)
    }",
    has last_seen_month "${
      incident.last_seen ? monthFormat(incident.last_seen) : monthFormat(now)
    }",
    has last_seen_year "${
      incident.last_seen ? yearFormat(incident.last_seen) : yearFormat(now)
    }",
    has created ${incident.created ? prepareDate(incident.created) : now},
    has modified ${incident.modified ? prepareDate(incident.modified) : now},
    has revoked false,
    has created_at ${now},
    has created_at_day "${dayFormat(now)}",
    has created_at_month "${monthFormat(now)}",
    has created_at_year "${yearFormat(now)}", 
    has updated_at ${now};
  `;
    logger.debug(`[GRAKN - infer: false] addIncident > ${query}`);
    const incidentIterator = await wTx.tx.query(query);
    const createdIncident = await incidentIterator.next();
    const createdIncidentId = await createdIncident.map().get('incident').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdIncidentId, incident.createdByRef);
    await linkMarkingDef(wTx, createdIncidentId, incident.markingDefinitions);
    return internalId;
  });
  return refetchEntityById(incidentId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
