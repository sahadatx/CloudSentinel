import { Navigate, Route, Routes } from "react-router-dom";
import { Component, lazy, Suspense } from "react";
import type { ComponentType, ReactNode } from "react";
import { useAuth } from "../shared/useAuth";
import { Shell } from "./Shell";

function lazyNamed<TModule, TName extends keyof TModule>(
  importModule: () => Promise<TModule>,
  exportName: TName,
) {
  return lazy(async () => ({
    default: (await importModule())[exportName] as ComponentType,
  }));
}

const LoginPage = lazyNamed(() => import("../pages/LoginPage"), "LoginPage");
const ForgotPasswordPage = lazyNamed(() => import("../pages/LoginPage"), "ForgotPasswordPage");
const ForcePasswordChangePage = lazyNamed(() => import("../pages/PasswordWorkflowPages"), "ForcePasswordChangePage");
const InvitationAcceptancePage = lazyNamed(() => import("../pages/PasswordWorkflowPages"), "InvitationAcceptancePage");
const ResetPasswordPage = lazyNamed(() => import("../pages/PasswordWorkflowPages"), "ResetPasswordPage");
const SsoCallbackPage = lazyNamed(() => import("../pages/SsoCallbackPage"), "SsoCallbackPage");
const AccountDetailPage = lazyNamed(() => import("../pages/CloudAccountsPage"), "AccountDetailPage");
const AccountsPage = lazyNamed(() => import("../pages/CloudAccountsPage"), "AccountsPage");
const ConnectAWSPage = lazyNamed(() => import("../pages/CloudAccountsPage"), "ConnectAWSPage");
const OrganizationPage = lazyNamed(() => import("../pages/AdministrationPages"), "OrganizationPage");
const SettingsPage = lazyNamed(() => import("../pages/AdministrationPages"), "SettingsPage");
const TeamDetailsPage = lazyNamed(() => import("../pages/AdministrationPages"), "TeamDetailsPage");
const TeamsPage = lazyNamed(() => import("../pages/AdministrationPages"), "TeamsPage");
const UserDetailsPage = lazyNamed(() => import("../pages/AdministrationPages"), "UserDetailsPage");
const UsersPage = lazyNamed(() => import("../pages/AdministrationPages"), "UsersPage");
const AssetDetailPage = lazyNamed(() => import("../pages/Pages"), "AssetDetailPage");
const AlertsPage = lazyNamed(() => import("../pages/Pages"), "AlertsPage");
const AssetsPage = lazyNamed(() => import("../pages/Pages"), "AssetsPage");
const AuditPage = lazyNamed(() => import("../pages/Pages"), "AuditPage");
const CompliancePage = lazyNamed(() => import("../pages/Pages"), "CompliancePage");
const ComplianceControlDetailsPage = lazyNamed(() => import("../pages/Pages"), "ComplianceControlDetailsPage");
const DashboardPage = lazyNamed(() => import("../pages/Pages"), "DashboardPage");
const FindingDetailPage = lazyNamed(() => import("../pages/Pages"), "FindingDetailPage");
const FindingsPage = lazyNamed(() => import("../pages/Pages"), "FindingsPage");
const NotificationsPage = lazyNamed(() => import("../pages/Pages"), "NotificationsPage");
const ProfilePage = lazyNamed(() => import("../pages/Pages"), "ProfilePage");
const ReportDetailPage = lazyNamed(() => import("../pages/Pages"), "ReportDetailPage");
const RemediationPage = lazyNamed(() => import("../pages/Pages"), "RemediationPage");
const RemediationDetailPage = lazyNamed(() => import("../pages/Pages"), "RemediationDetailPage");
const ReportsPage = lazyNamed(() => import("../pages/Pages"), "ReportsPage");
const RiskPage = lazyNamed(() => import("../pages/Pages"), "RiskPage");
const SessionsPage = lazyNamed(() => import("../pages/Pages"), "SessionsPage");
const PoliciesPage = lazyNamed(() => import("../pages/PolicyPages"), "PoliciesPage");
const PolicyDetailsPage = lazyNamed(() => import("../pages/PolicyPages"), "PolicyDetailsPage");
const ScanDetailPage = lazyNamed(() => import("../pages/ScanPages"), "ScanDetailPage");
const ScansPage = lazyNamed(() => import("../pages/ScanPages"), "ScansPage");
const CustomerScanDetailPage = lazyNamed(() => import("../pages/CustomerScansPage"), "CustomerScanDetailPage");
const CustomerScansPage = lazyNamed(() => import("../pages/CustomerScansPage"), "CustomerScansPage");

class AppErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error): { error: Error } {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("CloudSentinel page render failed", error);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="loading-screen" role="alert">
          <strong>Page could not be displayed.</strong>
          <span>Refresh the page or contact your administrator.</span>
          <button type="button" onClick={() => window.location.reload()}>
            Reload page
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function PermissionGate({
  permission,
  children,
}: {
  permission: string;
  children: ReactNode;
}) {
  const { user } = useAuth();
  return user?.permissions.includes(permission) ? (
    <>{children}</>
  ) : (
    <Navigate to="/" replace />
  );
}

function AnyPermissionGate({
  permissions,
  children,
}: {
  permissions: string[];
  children: ReactNode;
}) {
  const { user } = useAuth();
  return permissions.some((permission) => user?.permissions.includes(permission)) ? (
    <>{children}</>
  ) : (
    <Navigate to="/" replace />
  );
}

export function App() {
  const { user, ready } = useAuth();
  if (!ready)
    return (
      <div className="loading-screen">
        CloudSentinel <span>Loading secure session…</span>
      </div>
    );
  return (
    <Suspense fallback={<div className="loading-screen">CloudSentinel <span>Loading page…</span></div>}>
    <AppErrorBoundary>
    <Routes>
      <Route
        path="/login"
        element={user ? <Navigate to={user.force_password_change ? "/force-password-change" : "/"} replace /> : <LoginPage />}
      />
      <Route path="/forgot-password" element={user ? <Navigate to={user.force_password_change ? "/force-password-change" : "/"} replace /> : <ForgotPasswordPage />} />
      <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/accept-invitation" element={<InvitationAcceptancePage />} />
      <Route path="/sso/callback" element={<SsoCallbackPage />} />
      <Route path="/force-password-change" element={!user ? <Navigate to="/login" replace /> : user.force_password_change ? <ForcePasswordChangePage /> : <Navigate to="/" replace />} />
      <Route element={!user ? <Navigate to="/login" replace /> : user.force_password_change ? <Navigate to="/force-password-change" replace /> : <Shell />}>
        <Route path="profile" element={<ProfilePage />} />
        <Route path="profile/sessions" element={<SessionsPage />} />
        <Route
          index
          element={<Navigate to="/dashboard" replace />}
        />
        <Route path="dashboard" element={<PermissionGate permission="organizations:read"><DashboardPage /></PermissionGate>} />
        <Route
          path="cloud-accounts"
          element={
            <PermissionGate permission="cloud_accounts:read">
              <AccountsPage />
            </PermissionGate>
          }
        />
        <Route
          path="cloud-accounts/connect"
          element={
            <AnyPermissionGate permissions={["cloud_accounts:create", "cloud_accounts:update"]}>
              <ConnectAWSPage />
            </AnyPermissionGate>
          }
        />
        <Route
          path="cloud-accounts/:accountId"
          element={
            <PermissionGate permission="cloud_accounts:read">
              <AccountDetailPage />
            </PermissionGate>
          }
        />
        <Route path="scans" element={<PermissionGate permission="scans:read"><ScansPage /></PermissionGate>} />
        <Route path="scans/:scanId" element={<PermissionGate permission="scans:read"><ScanDetailPage /></PermissionGate>} />
        <Route path="customer-scans" element={<PermissionGate permission="scans:read"><CustomerScansPage /></PermissionGate>} />
        <Route path="customer-scans/:scanId" element={<PermissionGate permission="scans:read"><CustomerScanDetailPage /></PermissionGate>} />
        <Route
          path="assets"
          element={
            <PermissionGate permission="assets:read">
              <AssetsPage />
            </PermissionGate>
          }
        />
        <Route
          path="assets/:assetId"
          element={
            <PermissionGate permission="assets:read">
              <AssetDetailPage />
            </PermissionGate>
          }
        />
        <Route
          path="findings"
          element={
            <PermissionGate permission="findings:read">
              <FindingsPage />
            </PermissionGate>
          }
        />
        <Route
          path="findings/:findingId"
          element={
            <PermissionGate permission="findings:read">
              <FindingDetailPage />
            </PermissionGate>
          }
        />
        <Route
          path="policies"
          element={
            <PermissionGate permission="policies:read">
              <PoliciesPage />
            </PermissionGate>
          }
        />
        <Route
          path="policies/:policyId"
          element={
            <PermissionGate permission="policies:read">
              <PolicyDetailsPage />
            </PermissionGate>
          }
        />
        <Route
          path="risk"
          element={
            <PermissionGate permission="findings:read">
              <RiskPage />
            </PermissionGate>
          }
        />
        <Route
          path="compliance"
          element={
            <PermissionGate permission="findings:read">
              <CompliancePage />
            </PermissionGate>
          }
        />
        <Route
          path="compliance/:controlId"
          element={
            <PermissionGate permission="findings:read">
              <ComplianceControlDetailsPage />
            </PermissionGate>
          }
        />
        <Route
          path="remediation"
          element={
            <PermissionGate permission="remediation:read">
              <RemediationPage />
            </PermissionGate>
          }
        />
        <Route path="remediation/:remediationId" element={<PermissionGate permission="remediation:read"><RemediationDetailPage /></PermissionGate>} />
        <Route
          path="reports"
          element={
            <PermissionGate permission="reports:read">
              <ReportsPage />
            </PermissionGate>
          }
        />
        <Route
          path="reports/:reportId"
          element={
            <PermissionGate permission="reports:read">
              <ReportDetailPage />
            </PermissionGate>
          }
        />
        <Route
          path="alerts"
          element={
            <PermissionGate permission="alerts:read">
              <AlertsPage />
            </PermissionGate>
          }
        />
        <Route path="notifications" element={<PermissionGate permission="organizations:read"><NotificationsPage /></PermissionGate>} />
        <Route
          path="audit"
          element={
            <PermissionGate permission="audit:read">
              <AuditPage />
            </PermissionGate>
          }
        />
        <Route path="administration" element={<Navigate to="/administration/organization" replace />} />
        <Route path="administration/organization" element={<PermissionGate permission="organizations:read"><OrganizationPage /></PermissionGate>} />
        <Route path="administration/users" element={<PermissionGate permission="users:read"><UsersPage /></PermissionGate>} />
        <Route path="administration/users/:user_id" element={<PermissionGate permission="users:read"><UserDetailsPage /></PermissionGate>} />
        <Route path="administration/teams" element={<PermissionGate permission="teams:read"><TeamsPage /></PermissionGate>} />
        <Route path="administration/teams/:team_id" element={<PermissionGate permission="teams:read"><TeamDetailsPage /></PermissionGate>} />
        <Route path="administration/settings" element={<PermissionGate permission="organizations:read"><SettingsPage /></PermissionGate>} />
        <Route path="administration/settings/:section" element={<PermissionGate permission="organizations:read"><SettingsPage /></PermissionGate>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
    </AppErrorBoundary>
    </Suspense>
  );
}
