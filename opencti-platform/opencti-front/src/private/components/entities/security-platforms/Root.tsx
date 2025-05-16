import { useParams } from 'react-router-dom';
import React, { Suspense } from 'react';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const Root = () => {
  const { sectorId } = useParams() as { sectorId: string; };
  // const queryRef = useQueryLoading<>(
  //   // sectorQuery, {
  //   // id,
  // });

  return (
    <>
      {/* {queryRef && ( */}
      <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
        {/* <RootSector sectorId={sectorId} queryRef={queryRef} /> */}
      </Suspense>
      {/* )} */}
    </>
  );
};

export default Root;
