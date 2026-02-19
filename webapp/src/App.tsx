import { Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './components/Layout'
import { RequireAuth } from './components/RequireAuth'
import { LoginPage } from './pages/LoginPage'
import { UserPlansPage } from './pages/user/UserPlansPage'
import { UserPurchaseNewPage } from './pages/user/UserPurchaseNewPage'
import { UserPurchaseHistoryPage } from './pages/user/UserPurchaseHistoryPage'
import { UserKeysPage } from './pages/user/UserKeysPage'
import { UserUsagePage } from './pages/user/UserUsagePage'
import { AdminOverviewPage } from './pages/admin/AdminOverviewPage'
import { AdminPurchasesPage } from './pages/admin/AdminPurchasesPage'
import { AdminUsersPage } from './pages/admin/AdminUsersPage'
import { AdminUsageControlsPage } from './pages/admin/AdminUsageControlsPage'
import { AdminPlansPage } from './pages/admin/AdminPlansPage'

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route
        path="/user/*"
        element={
          <RequireAuth role="user">
            <AppLayout title="User Console" role="user">
              <Routes>
                <Route path="plans" element={<UserPlansPage />} />
                <Route path="purchase/new" element={<UserPurchaseNewPage />} />
                <Route path="purchase/history" element={<UserPurchaseHistoryPage />} />
                <Route path="keys" element={<UserKeysPage />} />
                <Route path="usage" element={<UserUsagePage />} />
                <Route path="*" element={<Navigate to="plans" replace />} />
              </Routes>
            </AppLayout>
          </RequireAuth>
        }
      />

      <Route
        path="/admin/*"
        element={
          <RequireAuth role="admin">
            <AppLayout title="Admin Console" role="admin">
              <Routes>
                <Route path="overview" element={<AdminOverviewPage />} />
                <Route path="purchases" element={<AdminPurchasesPage />} />
                <Route path="users" element={<AdminUsersPage />} />
                <Route path="usage-controls" element={<AdminUsageControlsPage />} />
                <Route path="plans" element={<AdminPlansPage />} />
                <Route path="*" element={<Navigate to="overview" replace />} />
              </Routes>
            </AppLayout>
          </RequireAuth>
        }
      />

      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  )
}
