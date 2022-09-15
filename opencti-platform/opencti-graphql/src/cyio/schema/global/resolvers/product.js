import {compareValues, filterValues} from '../../utils.js';
import {ApolloError, UserInputError} from "apollo-server-express";
// import {ApolloError, UserInputError} from 'apollo-server-errors';
import {
  getReducer, 
  countProductsQuery,
  selectAllProducts,
  selectProductQuery,
  productSingularizeSchema as singularizeSchema,
} from './product-sparqlQuery.js';

const productResolvers = {
  Query: {
    products: async (_, args, { dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (const [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
          }
        }
      }
      // END WORKAROUND

      if ('search' in args && ('first' in args || 'offset' in args)) throw new ApolloError("Query can not have both 'search' and 'first'/'offset'", "BAD_USER_INPUT");
      if ('offset' in args && !('first' in args)) throw new ApolloError("Argument 'offset' can not be used without 'first'", "BAD_USER_INPUT");

      const dbName = 'cyber-context';
      let response;

      let limitValue = ('first' in args ? args['first'] : undefined)
      let offsetValue = ('offset' in args ? args['offset'] : 0);

      // count how may instances exist
      const countQuery = countProductsQuery(args);
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery: countQuery,
          queryId: "Count Products",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // no components found
      if (response === undefined || response.length === 0) return null;
      const totalProductCount = response[0].count;

      // too many products to return, so ask user to refine the search
      if (totalProductCount > 1000) throw new ApolloError("Your search returned too many results. Please narrow your query.", "BAD_USER_INPUT");

      // Select the list of products
      const sparqlQuery = selectAllProducts(selectMap.getNode("node"), args);
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Product list",
          limitValue,
          offsetValue,
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // no components found
      if (response === undefined || response.length === 0) return null;
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        const reducer = getReducer("PRODUCT");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let productList ;
        if (args.orderedBy !== undefined ) {
          productList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          productList = response;
        }

        if (offset > totalProductCount) return null;

        // for each product in the result set
        for (let product of productList) {
          if (product.id === undefined || product.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${product.iri} missing field 'id'`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(product, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if ( limit ) {
            let edge = {
              cursor: product.iri,
              node: reducer( product ),
            }
            edges.push( edge )
            limit-- ;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        resultCount = totalProductCount;
        if ('search' in args) resultCount = edges.length;

        // determine if there is more data
        let hasNextPage = false, hasPreviousPage = false;
        if (offsetSize != 0 && offsetSize < resultCount) hasNextPage = true;
        if (offsetSize > 0) hasPreviousPage = true;

        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (hasNextPage ),
            hasPreviousPage: (hasPreviousPage),
            globalCount: resultCount,
          },
          edges: edges,
        }
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return[];
        }
      } 
    },
    product: async (_, {id}, {dataSources, selectMap}) => {
      const dbName = 'cyber-context';
      const sparqlQuery = selectProductQuery(id, selectMap.getNode("product"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Product",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // no components found
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("PRODUCT");
        const first = response[0];
        if (first === undefined) return null;
        return (reducer(first));
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }      
    },
  },
  Mutation: {},
  Product: {
    __resolveType: ( item ) => {
      if (item.entity_type == 'hardware') return 'HardwareProduct';
      if (item.entity_type === 'software') return 'SoftwareProduct';
    }
  },
  SoftwareProduct: {},
};

export default productResolvers;
