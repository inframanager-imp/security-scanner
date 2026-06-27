import type { ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import { AppLayout } from './components/layout/AppLayout';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { AccountDetail } from './pages/AccountDetail';
import { ScanDetail } from './pages/ScanDetail';
import { Reports } from './pages/Reports';
import { AccountReport } from './pages/AccountReport';
import { CloudTrailLogs } from './pages/CloudTrailLogs';
import { Compliance } from './pages/Compliance';
import { AccountCompliance } from './pages/AccountCompliance';
import { ContainerSecurity } from './pages/ContainerSecurity';
import { ThreatDetection } from './pages/ThreatDetection';
import { AzureSubscriptionDetail } from './pages/AzureSubscriptionDetail';
import { AzureActivityLogs } from './pages/AzureActivityLogs';
import { CloudSubscriptions } from './pages/CloudSubscriptions';
import { GcpProjectDetail } from './pages/GcpProjectDetail';
import { AzureSubscriptionReport } from './pages/AzureSubscriptionReport';
import { AzureSubscriptionCompliance } from './pages/AzureSubscriptionCompliance';
import { ConfigChanges }       from './pages/ConfigChanges';
import { ConfigChangesReport } from './pages/ConfigChangesReport';
import AlertConfiguration      from './pages/AlertConfiguration';
import FreezeWindows           from './pages/FreezeWindows';
import PostureScore            from './pages/PostureScore';
import BaselineDrift           from './pages/BaselineDrift';
import ScheduledReports        from './pages/ScheduledReports';
import Integrations            from './pages/Integrations';
import IamEscalation           from './pages/IamEscalation';
import { RiskRegister }        from './pages/RiskRegister';
import { ResourceInventory }   from './pages/ResourceInventory';
import { ResourceDetail }      from './pages/ResourceDetail';
import { AssetGraph }          from './pages/AssetGraph';
import { IdentityGraph }       from './pages/IdentityGraph';
import { AttackPathDetail }    from './pages/AttackPathDetail';
import { PrioritizedRisks }    from './pages/PrioritizedRisks';
import { WorkloadVulnerabilities } from './pages/WorkloadVulnerabilities';
import { DataSecurity }         from './pages/DataSecurity';
import AspmWorkspace            from './pages/AspmWorkspace';
import { ReportsHub }           from './pages/ReportsHub';
import IntegrationsHub          from './pages/IntegrationsHub';

interface ProtectedRouteProps {
  children: ReactNode;
}

function ProtectedRoute({ children }: ProtectedRouteProps) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<Login />} />

      {/* Protected routes */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="cloud" element={<CloudSubscriptions />} />
        <Route path="appsec" element={<Navigate to="/appsec/overview" replace />} />
        <Route path="appsec/:module" element={<AspmWorkspace />} />
        <Route path="accounts" element={<Navigate to="/cloud" replace />} />
        <Route path="accounts/:id" element={<AccountDetail />} />
        <Route path="scans/:id" element={<ScanDetail />} />
        <Route path="reports" element={<ReportsHub />} />
        <Route path="reports/:accountId" element={<AccountReport />} />
        <Route path="reports/azure/:id" element={<AzureSubscriptionReport />} />
        <Route path="cloudtrail" element={<CloudTrailLogs />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="compliance/:accountId" element={<AccountCompliance />} />
        <Route path="compliance/azure/:subscriptionId" element={<AzureSubscriptionCompliance />} />
        <Route path="containers" element={<ContainerSecurity />} />
        <Route path="threats" element={<ThreatDetection />} />
        <Route path="azure" element={<Navigate to="/cloud" replace />} />
        <Route path="azure/:id" element={<AzureSubscriptionDetail />} />
        <Route path="azure-activity" element={<AzureActivityLogs />} />
        <Route path="gcp" element={<Navigate to="/cloud" replace />} />
        <Route path="gcp/:id" element={<GcpProjectDetail />} />
        <Route path="config-changes" element={<ConfigChanges />} />
        <Route path="config-changes/:provider/:id" element={<ConfigChangesReport />} />
        <Route path="alerts" element={<AlertConfiguration />} />
        <Route path="freeze-windows" element={<FreezeWindows />} />
        <Route path="posture-score" element={<PostureScore />} />
        <Route path="baselines" element={<BaselineDrift />} />
        <Route path="scheduled-reports" element={<ScheduledReports />} />
        <Route path="integrations" element={<IntegrationsHub />} />
        <Route path="iam-escalation" element={<IamEscalation />} />
        <Route path="risk-register"      element={<RiskRegister />} />
        <Route path="resource-inventory"      element={<ResourceInventory />} />
        <Route path="resource-inventory/:id"  element={<ResourceDetail />} />
        <Route path="asset-graph"             element={<AssetGraph />} />
        <Route path="identity-graph"          element={<IdentityGraph />} />
        <Route path="attack-paths/:id"        element={<AttackPathDetail />} />
        <Route path="prioritized-risks"       element={<PrioritizedRisks />} />
        <Route path="workload-vulns"          element={<WorkloadVulnerabilities />} />
        <Route path="data-security"           element={<DataSecurity />} />
      </Route>

      {/* Catch-all */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
