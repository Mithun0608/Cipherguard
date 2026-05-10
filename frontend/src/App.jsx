import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import Dashboard from './pages/Dashboard'
import ExperimentRunner from './pages/ExperimentRunner'
import AttackAnalysis from './pages/AttackAnalysis'
import AlgorithmComparison from './pages/AlgorithmComparison'
import SecurityScorecard from './pages/SecurityScorecard'
import SaltingVisualizer from './pages/SaltingVisualizer'
import BreachSimulator from './pages/BreachSimulator'
import LogsReports from './pages/LogsReports'
import Settings from './pages/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"    element={<Dashboard />} />
          <Route path="experiment"   element={<ExperimentRunner />} />
          <Route path="attacks"      element={<AttackAnalysis />} />
          <Route path="algorithms"   element={<AlgorithmComparison />} />
          <Route path="scorecard"    element={<SecurityScorecard />} />
          <Route path="salting"      element={<SaltingVisualizer />} />
          <Route path="breach"       element={<BreachSimulator />} />
          <Route path="logs"         element={<LogsReports />} />
          <Route path="settings"     element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
