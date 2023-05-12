#ifndef __INTELLISENSE__

// 计算以 2 为低的对数
static __always_inline unsigned long long log2(unsigned int v) {
    unsigned int shift, r;

    r = (v > 0xFFFF) << 4;
    v >>= r;
    shift = (v > 0xFF) << 3;
    v >>= shift;
    r |= shift;
    shift = (v > 0xF) << 2;
    v >>= shift;
    r |= shift;
    shift = (v > 0x3) << 1;
    v >>= shift;
    r |= shift;
    r |= (v >> 1);

    return r;
}

static __always_inline unsigned long long log2l(unsigned long long v) {
    unsigned int hi = v >> 32;

    if (hi) {
        return log2(hi) + 32;
    } else {
        return log2(v);
    }
}

#endif