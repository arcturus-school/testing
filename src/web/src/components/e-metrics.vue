<template>
  <div class="metrics-select-wrapper">
    <span class="metrics-label">指标:</span>
    <a-select
      class="metrics-select"
      :options="labels"
      v-model:value="label"
      @change="changeHandler"
    />
  </div>
</template>

<script setup lang="ts">
import { useStore } from '@src/store';
import { log } from '@utils/log';
import { storeToRefs } from 'pinia';

const store = useStore();

const { labels, label } = storeToRefs(store);

const changeHandler = function (value: string) {
  log(`select label: ${value}...`);

  store.getMetricData();
};
</script>

<style scoped lang="scss">
.metrics-select-wrapper {
  .metrics-select {
    min-width: 220px;
  }

  .metrics-label {
    margin-right: 10px;
  }
}
</style>
