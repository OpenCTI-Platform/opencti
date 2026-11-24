import { useEffect, useState } from 'react';
import { MESSAGING$ } from '../../relay/environment';

const readNavOpen = () => localStorage.getItem('navOpen') === 'true';

/** Whether the left navigation is open. Updates when the user opens or closes it. */
const useNavOpen = () => {
  const [navOpen, setNavOpen] = useState(readNavOpen);
  useEffect(() => {
    const sub = MESSAGING$.toggleNav.subscribe({ next: () => setNavOpen(readNavOpen()) });
    return () => sub.unsubscribe();
  }, []);
  return navOpen;
};

export default useNavOpen;
