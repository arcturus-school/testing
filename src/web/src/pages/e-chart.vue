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
import { Chart } from '@antv/g2';
import { watchEffect, nextTick } from 'vue';
import {
  setChart,
  drawHeatMap,
  drawLines,
  destroy,
  svgRenderer,
} from '@utils/draw';

const store = useStore();

const { label, loading, metricsData, chartType } = storeToRefs(store);

watchEffect(() => {
  if (loading.value) {
    destroy();
  } else {
    if (label.value != null) {
      nextTick(() => {
        destroy(); // 绘图前先销毁之前的图

        setChart(
          new Chart({
            container: 'chart',
            theme: 'classic',
            autoFit: true,
            renderer: svgRenderer,
          })
        );

        if (chartType.value === 'heapmap') {
          drawHeatMap(metricsData.value!);
        } else if (chartType.value == 'lines') {
          drawLines();
        }
      });
    }
  }
});
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
    bottom: 0;
  }
}
</style>
