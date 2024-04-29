import { Navigate, Route, Routes } from 'react-router-dom';
import React from 'react';
import Search from './Search';
import SearchContainerQuery from './search/SearchContainerQuery';
import SearchIndexedFiles from './search/SearchIndexedFiles';

const SearchFiles = () => {
  return (
    <SearchContainerQuery>
      <SearchIndexedFiles />
    </SearchContainerQuery>
  );
};

const SearchKnowledge = () => {
  return (
    <SearchContainerQuery>
      <Search />
    </SearchContainerQuery>
  );
};

const RootSearch = () => {
  return (
    <Routes>
      <Route path="/knowledge" element={<SearchKnowledge />} />
      <Route path="/knowledge/:keyword" element={<SearchKnowledge />} />
      <Route path="/files" element={<SearchFiles />} />
      <Route path="/files/:keyword" element={<SearchFiles />} />

      <Route path="/" element={<Navigate to="/dashboard/search/knowledge" />} />
    </Routes>
  );
};

export default RootSearch;
