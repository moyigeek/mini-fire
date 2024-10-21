import { createRouter, createWebHistory } from 'vue-router';
import FirewallStatus from '../components/FirewallStatus.vue';
import Logs from '../components/Logs.vue';
import RuleFilter from '../components/RuleFilter.vue';
import NatManagement from '../components/NatManagement.vue';
import ConnectionTable from '../components/ConnectionTable.vue';

const routes = [
  { path: '/', component: FirewallStatus },
  { path: '/logs', component: Logs },
  { path: '/rule-filter', component: RuleFilter },
  { path: '/nat-management', component: NatManagement },
  { path: '/connection-table', component: ConnectionTable },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;