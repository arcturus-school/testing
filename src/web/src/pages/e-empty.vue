<template>
  <div class="wrapper center">
    <a-empty :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂无数据" />
  </div>
</template>

<script setup lang="ts">
import { Empty } from 'ant-design-vue';
</script>

<style scoped lang="scss">
.wrapper {
  flex: 1;
}
</style>
