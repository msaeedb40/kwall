import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    redirectTo: 'dashboard',
  },
  {
    path: 'dashboard',
    loadComponent: () =>
      import('./features/dashboard/dashboard.component').then(
        (m) => m.DashboardComponent
      ),
  },
  {
    path: 'flows',
    loadComponent: () =>
      import('./features/flows/flows.component').then((m) => m.FlowsComponent),
  },
  {
    path: 'security',
    loadComponent: () =>
      import('./features/security/security.component').then(
        (m) => m.SecurityComponent
      ),
  },
  {
    path: 'workloads',
    loadComponent: () =>
      import('./features/workloads/workloads.component').then(
        (m) => m.WorkloadsComponent
      ),
  },
  {
    path: '**',
    redirectTo: 'dashboard',
  },
];
