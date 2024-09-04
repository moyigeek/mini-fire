#ifndef DRIVER_H
#define DRIVER_H

int register_firewall_device(void);
void unregister_firewall_device(void);
static int filter_status = 0; // 0: off, 1: on
#endif // DRIVER_H