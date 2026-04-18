/* ============================================
   GUARDIANHEALTH — SPA ROUTER
   ============================================ */
(function() {
  const routes = {
    '': 'login', '/': 'login', '/login': 'login',
    '/register': 'register',
    '/admin': 'admin', '/doctor': 'doctor',
    '/patient': 'patient', '/staff': 'staff',
    '/security': 'security', '/iam': 'iam',
    '/audit-logs': 'auditlogs', '/settings': 'settings'
  };

  const pageMap = {
    login: window.LoginPage,
    register: window.RegisterPage,
    admin: window.AdminPage,
    doctor: window.DoctorPage,
    patient: window.PatientPage,
    staff: window.StaffPage,
    security: window.SecurityPage,
    iam: window.IAMPage,
    auditlogs: window.AuditLogsPage,
    settings: window.SettingsPage
  };

  const publicRoutes = ['login', 'register'];

  function navigate() {
    const hash = window.location.hash.replace('#', '') || '/';
    const pageName = routes[hash] || 'login';
    const user = window.Auth.getUser();

    if (!user && !publicRoutes.includes(pageName)) {
      window.location.hash = '#/login';
      return;
    }
    if (user && (pageName === 'login' || pageName === 'register')) {
      window.Auth.redirectByRole(user.role);
      return;
    }

    const page = pageMap[pageName];
    const app = document.getElementById('app');
    if (page) {
      app.innerHTML = page.render(user);
      if (page.mount) page.mount(user);
      // Re-init Lucide icons
      if (window.lucide) window.lucide.createIcons();
      // Scroll to top
      window.scrollTo(0, 0);
    } else {
      app.innerHTML = `<div class="flex-center" style="min-height:100vh;flex-direction:column;gap:16px;"><h1 style="font-size:24px;font-weight:700;">Page not found</h1><a href="#/login" style="color:var(--primary);">Go Home</a></div>`;
    }
  }

  window.addEventListener('hashchange', navigate);
  window.addEventListener('DOMContentLoaded', () => {
    navigate();
  });

  // Global logout helper
  window.doLogout = function() {
    window.Auth.logout();
    window.location.hash = '#/login';
  };

  // Sidebar mobile toggle
  window.toggleSidebar = function() {
    const s = document.getElementById('sidebar');
    if (s) s.classList.toggle('mobile-open');
    const dim = document.getElementById('sidebar-dimmer');
    if (dim) dim.classList.toggle('hidden');
  };
  window.closeSidebar = function() {
    const s = document.getElementById('sidebar');
    if (s) s.classList.remove('mobile-open');
    const dim = document.getElementById('sidebar-dimmer');
    if (dim) dim.classList.add('hidden');
  };
})();
