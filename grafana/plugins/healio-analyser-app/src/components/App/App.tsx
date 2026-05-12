import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { AppRootProps } from '@grafana/data';
import { ROUTES } from '../../constants';

// Static imports — no code splitting, no chunk loading
import OverviewPage from '../../pages/OverviewPage';
import AnalysisPage from '../../pages/AnalysisPage';
import FleetPage from '../../pages/FleetPage';
import ThreatIntelPage from '../../pages/ThreatIntelPage';

export default function App(props: AppRootProps) {
  return (
    <Routes>
      <Route path={ROUTES.Home}        element={<OverviewPage />} />
      <Route path={ROUTES.Analysis}    element={<AnalysisPage />} />
      <Route path={ROUTES.Fleet}       element={<FleetPage />} />
      <Route path={ROUTES.ThreatIntel} element={<ThreatIntelPage />} />
    </Routes>
  );
}
