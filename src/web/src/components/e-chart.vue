<template>
  <div class="chart-wrapper center">
    <a-empty
      v-if="!label"
      :image="Empty.PRESENTED_IMAGE_SIMPLE"
      description="暂无数据"
    />

    <a-spin v-else-if="loading" />

    <div v-else id="chart"></div>
  </div>
</template>

<script lang="ts" setup>
import { useStore } from '@src/store';
import { storeToRefs } from 'pinia';
import { Empty } from 'ant-design-vue';

const store = useStore();

const { label, loading } = storeToRefs(store);
</script>

<style scoped lang="scss">
.chart-wrapper {
  flex: 1;
}
</style>
