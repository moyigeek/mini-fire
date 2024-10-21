<template>
  <nav>
    <ul>
      <li><router-link to="/">Firewall Status</router-link></li>
      <li><router-link to="/logs">Logs</router-link></li>
      <li><router-link to="/rule-filter">Rule Filter</router-link></li>
      <li><router-link to="/nat-management">NAT Management</router-link></li>
      <li><router-link to="/connection-table">Connection Table</router-link></li>
    </ul>
  </nav>
</template>

<script setup>
</script>

<style scoped>
nav ul {
  list-style-type: none;
  padding: 0;
}

nav li {
  margin: 10px 0;
}
</style>