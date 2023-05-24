<template>
  <a-button class="time-select-wrapper" @click="() => (visible = true)">
    <template #icon>
      <field-time-outlined style="font-size: 16px" />
    </template>
    {{ timeRange }}
  </a-button>

  <a-modal
    v-model:visible="visible"
    title="时间范围"
    :footer="null"
    class="time-select-modal"
  >
    <a-input-search
      v-model:value="searchValue"
      placeholder="搜索时间范围"
      class="width-100"
      @search="onSearch"
    />

    <a-list
      size="small"
      class="width-100 list-wrapper"
      :data-source="opts"
      :split="false"
    >
      <template #renderItem="{ item }">
        <a-list-item class="clickable" @click="clickItem(item)">
          {{ item.label }}
        </a-list-item>
      </template>
    </a-list>

    <a-range-picker
      class="width-100"
      show-time
      format="YYYY-MM-DD HH:mm:ss"
      v-model:value="date"
    />

    <div class="confirm-btn-wrapper">
      <a-button type="primary" @click="confirm"> 确定 </a-button>
    </div>
  </a-modal>
</template>

<script lang="ts" setup>
import { FieldTimeOutlined } from '@ant-design/icons-vue';
import { useStore } from '@src/store';
import { log } from '@utils/log';
import type { Dayjs } from 'dayjs';
import { computed, ref } from 'vue';

const store = useStore();

const visible = ref(false);

const date = ref<[Dayjs, Dayjs]>();

interface Option {
  value: number;
  label: string;
}

const options = ref<Option[]>([
  {
    value: 300 /* timestamp */,
    label: '最近 5 分钟',
  },
  {
    value: 900,
    label: '最近 15 分钟',
  },
  {
    value: 1800,
    label: '最近 30 分钟',
  },
  {
    value: 3600,
    label: '最近 1 小时',
  },
  {
    value: 10800,
    label: '最近 3 小时',
  },
  {
    value: 21600,
    label: '最近 6 小时',
  },
  {
    value: 43200,
    label: '最近 12 小时',
  },
  {
    value: 86400,
    label: '最近 24 小时',
  },
]);

const timeRange = ref(options.value[1].label);

const searchValue = ref('');

const onSearch = function (value: string) {
  log(`time range search: ${value}...`);
};

const opts = computed(() => {
  return options.value.filter((v) => v.label.includes(searchValue.value));
});

const clickItem = function (item: Option) {
  log(`time range select: ${item.value}`);

  store.$patch({
    dt: item.value,
    start: null,
    end: null,
  });

  timeRange.value = item.label;
  visible.value = false; /* close the modal */
};

const confirm = function () {
  visible.value = false;

  if (typeof date.value !== 'undefined') {
    log(`time range input:`, date.value);

    store.$patch({
      start: date.value[0].valueOf() / 1000,
      end: date.value[1].valueOf() / 1000,
      dt: 0,
    });

    const d1 = date.value[0].format('YYYY-MM-DD HH:mm:ss');
    const d2 = date.value[1].format('YYYY-MM-DD HH:mm:ss');
    timeRange.value = `${d1}-${d2}`;
    date.value = undefined;
  }
};
</script>

<style scoped lang="scss">
.time-select-modal {
  .list-wrapper {
    height: 200px;
    margin: 6px 0;
    overflow-y: hidden;

    &:hover {
      overflow-y: overlay;
    }
  }

  .confirm-btn-wrapper {
    text-align: right;
    margin-top: 12px;
  }
}

:deep(.ant-list-item) {
  padding: 8px !important;

  &:hover {
    margin-right: 6px;
    background: #f5f5f5;
  }
}

.time-select-wrapper {
  min-width: 100px;
  text-align: left;
  padding-left: 12px;
  padding-right: 12px;

  .anticon {
    display: inline-block;
  }
}
</style>
