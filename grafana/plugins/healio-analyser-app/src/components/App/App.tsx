import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { AppRootProps } from '@grafana/data';

import { ROUTES } from '../../constants';

const OverviewPage = React.lazy(() => import('../../pages/OverviewPage'));
const AnalysisPage = React.lazy(() => import('../../pages/AnalysisPage'));
const FleetPage = React.lazy(() => import('../../pages/FleetPage'));
const ThreatIntelPage = React.lazy(() => import('../../pages/ThreatIntelPage'));

export default function App(props: AppRootProps) {
  return (
    <Routes>
      <Route path={ROUTES.Home} element={<OverviewPage />} />
      <Route path={ROUTES.Analysis} element={<AnalysisPage />} />
      <Route path={ROUTES.History} element={<FleetPage />} />
      <Route path={ROUTES.ThreatIntel} element={<ThreatIntelPage />} />
    </Routes>
  );
}
