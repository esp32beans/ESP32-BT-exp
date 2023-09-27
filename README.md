# ESP32 Bluedroid Bluetooth Classic and BLE Dual Mode Scanner

Start the Bluedroid stack on ESP32 scanning in Bluetooth Classic and Low Energy
modes. This configuration is called Bluetooth (BT) dual mode or dual role.
Scanning dumps out information about BT devices/peripherals in pairing mode.
Pairing and connecting are not supported.

Dual mode only works on the original ESP32. Newer ESP32 chips which support BT
(for example, ESP32-S3), only support Low Energy (BLE) mode.

The Arduino ESP32-BT-exp program is designed to use the Bluedroid C API.

Sample output
```
BT:  xx:xx:xx:xx:xx:xx, COD: 0x2540, RSSI: -53
BT:  xx:xx:xx:xx:xx:xx, COD: 0x2540, RSSI: -52
BT:  xx:xx:xx:xx:xx:xx, COD: 0x2540, RSSI: -53
BT:  xx:xx:xx:xx:xx:xx, COD: 0x580, RSSI: -61, EIR NAME: BT3.0 Mouse
BT:  xx:xx:xx:xx:xx:xx, BDNAME: Bluetooth 5.1 Keyboard
BT:  xx:xx:xx:xx:xx:xx, COD: 0x40680, RSSI: -74, EIR NAME: BlueTooth Printer
BLE: xx:xx:xx:xx:xx:xx, RSSI: -50, UUID: 0x1812, APPEARANCE: 0x03c2, ADDR_TYPE: 'RANDOM', NAME: 'BT5.0 Mouse'
BLE: xx:xx:xx:xx:xx:xx, RSSI: -54, UUID: 0x1812, APPEARANCE: 0x03c2, ADDR_TYPE: 'RANDOM', NAME: 'Microsoft Bluetooth Mouse'
BLE: xx:xx:xx:xx:xx:xx, RSSI: -64, UUID: 0x0000, APPEARANCE: 0x0000, ADDR_TYPE: 'PUBLIC', NAME: 'BlueTooth Printer'
```

Lines that start with "BT:" are BT classic devices. Lines that start with
"BLE"" are BT low energy devices.

The "Microsoft Bluetooth Mouse" device is BLE only.

The "Bluetooth 5.1 Keyboard" device is classic only.

The "BT3.0 Mouse" and "BT5.0 Mouse" devices are from a trackball mouse. This an
example of dual mode device.

The "BlueTooth Printer" device is another dual mode device.

## References

* https://www.espressif.com/sites/default/files/documentation/btble_coexistence_demo_en.pdf

The document is useful but ESP32-BT-exp is designed for arduino-esp32 rather
than ESP-IDF. And ESP32-BT-exp does not include support for SPP, pairing, or
connecting. Nevertheless, the document is helpful.
