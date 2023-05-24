<template>
  <div class="chart-select-wrapper">
    <span class="chart-select-label">图表类型:</span>
    <a-select
      class="chart-select"
      :options="options"
      v-model:value="chartType"
      @change="selectChange"
    />
  </div>
</template>

<script setup lang="ts">
import { log } from '@utils/log';
import { options, useStore } from '@src/store';
import { storeToRefs } from 'pinia';

const { chartType } = storeToRefs(useStore());

const selectChange = function (value: string) {
  log(`select ${value}`);
};
</script>

<style scoped lang="scss">
.chart-select-wrapper {
  .chart-select {
    min-width: 100px;
  }

  .chart-select-label {
    margin-right: 10px;
  }
}
</style>
