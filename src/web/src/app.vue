<template>
  <a-config-provider :locale="locale">
    <a-layout>
      <a-layout-header>
        <a-space :size="20">
          <e-metrics />
        </a-space>
        <a-space :size="5">
          <e-time-select />
          <a-button @click="store.refreshData">
            <template #icon>
              <sync-outlined />
            </template>
          </a-button>
        </a-space>
      </a-layout-header>
      <a-layout-content>
        <router-view />
      </a-layout-content>
    </a-layout>
  </a-config-provider>
</template>

<script setup lang="ts">
import EMetrics from '@components/e-metrics.vue';
import ETimeSelect from '@components/e-time-select.vue';
import locale from 'ant-design-vue/es/locale/zh_CN';
import { SyncOutlined } from '@ant-design/icons-vue';
import { useStore } from '@src/store';

import dayjs from 'dayjs';
import 'dayjs/locale/zh';

dayjs.locale('zh-cn');

const store = useStore();

store.getLabels();
</script>

<style scoped lang="scss">
.ant-layout {
  min-height: 100vh;

  .ant-layout-header {
    background: #fff;
    display: flex;
    justify-content: space-between;
  }

  .ant-layout-content {
    flex: 1;
    display: flex;
    padding: 0px 50px;
    background-color: #fff;
  }
}
</style>
