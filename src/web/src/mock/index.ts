import Mock from 'mockjs';
import { log } from '@utils/log';

// mock data
import LABLES from '@mock/data/labels.json';

Mock.setup({ timeout: '1000' });

Mock.mock(/\/api\/v1\/label\/__name__\/values/g, LABLES);

log('mock loading complete...');
