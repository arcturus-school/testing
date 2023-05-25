<template>
  <div class="chart-wrapper center">
    <a-spin v-if="loading" />
    <div v-else id="chart"></div>
  </div>
</template>

<script lang="ts" setup>
import { useStore } from '@src/store';
import { storeToRefs } from 'pinia';
import { useRoute } from 'vue-router';
import { nextTick, watch } from 'vue';
import { drawHeatMap, drawCounter } from '@utils/draw';

const store = useStore();

const route = useRoute();

const { loading, metricsData, chartType } = storeToRefs(store);

watch(
  () => route.params.metrics,
  (n) => {
    store.getMetricData(n as string).then(() => {
      nextTick(() => {
        if (metricsData.value?.result.length !== 0) {
          if (chartType.value === 'bucket') {
            drawHeatMap('chart', metricsData.value!);
          } else if (chartType.value == 'counter') {
            drawCounter('chart', metricsData.value!);
          }
        }
      });
    });
  },
  {
    immediate: true,
  }
);
</script>

<style scoped lang="scss">
.chart-wrapper {
  flex: 1;
  position: relative;

  #chart {
    position: absolute !important;
    left: 0;
    right: 0;
    top: 0;
    bottom: 6px;
  }
}
</style>
