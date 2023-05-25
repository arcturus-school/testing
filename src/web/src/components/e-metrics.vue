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
import { useRouter, useRoute } from 'vue-router';
import { watchEffect } from 'vue';

const store = useStore();

const router = useRouter();
const route = useRoute();

const { labels, label, chartType } = storeToRefs(store);

function changeChartType(value: string) {
  if (value.endsWith('bucket')) {
    chartType.value = 'heatmap';
  } else if (value.endsWith('counter')) {
    chartType.value = 'lines';
  }
}

watchEffect(() => {
  label.value = (route.params.metrics as string) ?? '';
  changeChartType(label.value);
});

const changeHandler = function (value: string) {
  log(`select label: ${value}...`);

  changeChartType(value);

  router.push(value);
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
