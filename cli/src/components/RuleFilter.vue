<template>
    <div>
      <h2>Rule Filter</h2>
      <!-- Add form and table for managing rules -->
    </div>
  </template>
  
  <script setup>
  import { ref, onMounted } from 'vue';
  import { invoke } from '@tauri-apps/api/core';
  
  const rules = ref([]);
  
  onMounted(async () => {
    const csvData = await invoke('read_file', { path: 'net_rule.csv' });
    rules.value = parseCSV(csvData);
  });
  
  function parseCSV(data) {
    // Implement CSV parsing logic
  }
  
  function saveRules() {
    const csvData = convertToCSV(rules.value);
    invoke('write_file', { path: 'net_rule.csv', contents: csvData });
  }
  
  function convertToCSV(data) {
    // Implement CSV conversion logic
  }
  </script>