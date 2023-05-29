<template>
  <div class="chart-wrapper center">
    <a-spin v-if="loading" />
    <e-empty v-else-if="metricsData?.result.length === 0"></e-empty>
    <div ref="chart" id="chart"></div>
  </div>
</template>

<script lang="ts" setup>
import { useStore } from '@src/store';
import { storeToRefs } from 'pinia';
import { useRoute } from 'vue-router';
import EEmpty from '@pages/e-empty.vue';
import { watch, ref, onMounted, onUnmounted } from 'vue';
import {
  drawHeatMap,
  drawCounter,
  initChart,
  destroy,
  clear,
} from '@utils/draw';

const store = useStore();

const route = useRoute();

const chart = ref<HTMLDivElement>();

const { loading, metricsData, chartType, query } = storeToRefs(store);

onMounted(() => {
  initChart(chart.value!);
});

onUnmounted(() => {
  destroy();
});

watch(
  () => route.params.metrics,
  (n) => {
    // 清空画布
    clear();

    store.getMetricData(n as string).then(() => {
      if (metricsData.value?.result.length !== 0) {
        switch (chartType.value) {
          case 'bucket':
            drawHeatMap(metricsData.value!, query.value);
            break;
          case 'counter':
            drawCounter(metricsData.value!, query.value);
            break;
        }
      }
    });
  },
  { immediate: true }
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
