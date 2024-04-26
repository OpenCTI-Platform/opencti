import { Navigate, Route, Routes } from 'react-router-dom';
import React from 'react';
import SearchContainerQuery from '@components/SearchContainerQuery';
import SearchIndexedFiles from '@components/search/SearchIndexedFiles';
import Search from '@components/Search';

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
