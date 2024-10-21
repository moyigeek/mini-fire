<template>
  <div>
    <h2>Connection Table</h2>
    <pre>{{ connectionTable }}</pre>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

const connectionTable = ref('');

onMounted(async () => {
  connectionTable.value = await invoke('read_file', { path: 'connection_table' });
});
</script>