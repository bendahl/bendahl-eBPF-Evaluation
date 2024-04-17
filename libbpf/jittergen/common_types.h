#ifndef JITTERGEN_COMMON_TYPES_H
#define JITTERGEN_COMMON_TYPES_H

#define ACTION_JITTER 1
#define ACTION_DROP 2
#define ACTION_REORDER 3

const unsigned char IP_P_TCP = 0x06;
const unsigned char IP_P_UDP = 0x11;

enum setting {ACTIONS, PROTOCOL, PORT, PERCENT, MIN_LAT, MAX_LAT};

#endif //JITTERGEN_COMMON_TYPES_H
