import React from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import OrganizationsLines from './organizations/OrganizationsLines';
import Loader, { LoaderVariant } from '../../../components/Loader';

const Organizations = () => {
  const queryRef = true;
  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '23%',
        isSortable: true,
      },
      x_opencti_organization_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '23%',
        isSortable: false,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
    };
    return (
      <ListLines
        // sortBy={sortBy}
        // orderAsc={orderAsc}
        // dataColumns={dataColumns}
        // handleSort={this.handleSort.bind(this)}
        // handleSearch={this.handleSearch.bind(this)}
        // handleAddFilter={this.handleAddFilter.bind(this)}
        // handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        // handleToggleExports={this.handleToggleExports.bind(this)}
        // exportEntityType="Organization"
        // keyword={searchTerm}
        // filters={filters}
        // paginationOptions={paginationOptions}
        // numberOfElements={numberOfElements}
        availableFilterKeys={[
          'x_opencti_organization_type',
          'labelledBy',
          'markedBy',
          'createdBy',
          'created_start_date',
          'created_end_date',
        ]}
      >
        {queryRef && (
          <>
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <OrganizationsLines
                queryRef={queryRef}
                // paginationOptions={paginationOptions}
                // dataColumns={dataColumns}
                // setNumberOfElements={helpers.handleSetNumberOfElements}
                // selectedElements={selectedElements}
                // deSelectedElements={deSelectedElements}
                // onToggleEntity={onToggleEntity}
                // selectAll={selectAll}
              />
            </React.Suspense>
          </>
        )}
        {/* <QueryRenderer
          query={organizationsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <OrganizationsLines.tsx
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              onLabelClick={this.handleAddFilter.bind(this)}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        /> */}
      </ListLines>
    );
  };
  return (
    <div>
      Organization list
      {renderLines()}
    </div>
  );
};
export default Organizations;
