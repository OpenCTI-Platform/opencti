import { UserInputError } from 'apollo-server-errors';
// TODO: move all query builder exports to the note sparql schema file
import { selectNoteByIriQuery } from '../resolvers/sparql-query.js';
import { 
  getReducer,
  singularizeNoteSchema,
//   selectNoteByIriQuery,
} from '../schema/sparql/note.js';


export const findNoteByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectNoteByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Note",
      singularizeSchema: singularizeNoteSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  let reducer = getReducer('NOTE');
  return reducer(response[0]);
}
