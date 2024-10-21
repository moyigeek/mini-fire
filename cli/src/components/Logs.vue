<template>
  <div>
    <h2>Logs</h2>
    <pre>{{ logs }}</pre>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';


const logs = ref('');

onMounted(async () => {
  logs.value = await invoke('read_file', { path: 'log.txt' });
});
</script>