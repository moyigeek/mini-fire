<template>
  <div>
    <h2>Firewall Status</h2>
    <button @click="toggleFirewall">{{ firewallStatus ? 'Disable' : 'Enable' }} Firewall</button>
  </div>
</template>

<script setup>
import { ref } from 'vue';

const firewallStatus = ref(false);

function toggleFirewall() {
  firewallStatus.value = !firewallStatus.value;
  // Add logic to enable/disable firewall
}
</script>