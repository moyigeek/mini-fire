<template>
  <div id="app">
    <Sidebar />
    <router-view />
  </div>
</template>

<script setup>
import Sidebar from './components/Sidebar.vue';
</script>

<style>
#app {
  display: flex;
}
</style>