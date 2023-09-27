/*
 * MIT License
 *
 * Copyright (c) 2023 esp32beans@gmail.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "esp_bt_device.h"
#include "esp_bt_main.h"
#include "esp_gap_bt_api.h"
#if CONFIG_BT_BLE_ENABLED
#include "esp_gap_ble_api.h"
#include "esp_gatt_defs.h"
#include "esp_gattc_api.h"
#endif // CONFIG_BT_BLE_ENABLED

#define ESP_BD_ADDR_STR "%02x:%02x:%02x:%02x:%02x:%02x"
#define ESP_BD_ADDR_HEX(addr)                                                  \
  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
#define SIZEOF_ARRAY(a) (sizeof(a) / sizeof(*a))
#define DBG_PRINTF(...) Serial.printf(__VA_ARGS__)

static esp_bd_addr_t _peer_bd_addr;
static char _remote_name[ESP_BT_GAP_MAX_BDNAME_LEN + 1] = "Test Device";
static bool _isRemoteAddressSet;

static esp_err_t start_ble_scan(uint32_t seconds);

static bool get_name_from_eir(uint8_t *eir, char *bdname, uint8_t *bdname_len) {
  if (!eir || !bdname || !bdname_len) {
    return false;
  }

  uint8_t *rmt_bdname, rmt_bdname_len;
  *bdname = *bdname_len = rmt_bdname_len = 0;

  rmt_bdname = esp_bt_gap_resolve_eir_data(eir, ESP_BT_EIR_TYPE_CMPL_LOCAL_NAME,
                                           &rmt_bdname_len);
  if (!rmt_bdname) {
    rmt_bdname = esp_bt_gap_resolve_eir_data(
        eir, ESP_BT_EIR_TYPE_SHORT_LOCAL_NAME, &rmt_bdname_len);
  }
  if (rmt_bdname) {
    rmt_bdname_len = rmt_bdname_len > ESP_BT_GAP_MAX_BDNAME_LEN
                         ? ESP_BT_GAP_MAX_BDNAME_LEN
                         : rmt_bdname_len;
    memcpy(bdname, rmt_bdname, rmt_bdname_len);
    bdname[rmt_bdname_len] = 0;
    *bdname_len = rmt_bdname_len;
    return true;
  }
  return false;
}

static char *bda2str(esp_bd_addr_t bda, char *str, size_t size) {
  if (bda == NULL || str == NULL || size < 18) {
    return NULL;
  }

  uint8_t *p = bda;
  snprintf(str, size, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3],
           p[4], p[5]);
  return str;
}

static esp_err_t start_bt_scan(uint32_t seconds) {
  esp_err_t ret = ESP_OK;
  if ((ret = esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY,
                                        (int)(seconds / 1.28), 0)) != ESP_OK) {
    log_i("esp_bt_gap_start_discovery failed: %d", ret);
    return ret;
  }
  return ret;
}

static void esp_bt_gap_cb(esp_bt_gap_cb_event_t event,
                          esp_bt_gap_cb_param_t *param) {
  switch (event) {
  case ESP_BT_GAP_DISC_RES_EVT: {
    log_i("ESP_BT_GAP_DISC_RES_EVT properties=%d", param->disc_res.num_prop);
    char bda_str[18];
    log_i("Scanned device: %s", bda2str(param->disc_res.bda, bda_str, sizeof(bda_str)));
    DBG_PRINTF("\nBT:  %s", bda2str(param->disc_res.bda, bda_str, 18));
    uint8_t peer_bdname_len = 0;
    char peer_bdname[ESP_BT_GAP_MAX_BDNAME_LEN + 1];
    for (int i = 0; i < param->disc_res.num_prop; i++) {
      switch (param->disc_res.prop[i].type) {
      case ESP_BT_GAP_DEV_PROP_EIR:
        if (get_name_from_eir((uint8_t *)param->disc_res.prop[i].val,
                              peer_bdname, &peer_bdname_len)) {
          log_i("ESP_BT_GAP_DISC_RES_EVT : EIR : %s : %d", peer_bdname,
                peer_bdname_len);
          DBG_PRINTF(", EIR NAME: %s", peer_bdname);
          if (strlen(_remote_name) == peer_bdname_len &&
              strncmp(peer_bdname, _remote_name, peer_bdname_len) == 0) {
            log_v("ESP_BT_GAP_DISC_RES_EVT : SPP_START_DISCOVERY_EIR : %s",
                  peer_bdname, peer_bdname_len);
            _isRemoteAddressSet = true;
            memcpy(_peer_bd_addr, param->disc_res.bda, ESP_BD_ADDR_LEN);
            esp_bt_gap_cancel_discovery();
            // esp_spp_start_discovery(_peer_bd_addr);
          }
        }
        break;

      case ESP_BT_GAP_DEV_PROP_BDNAME:
        peer_bdname_len = param->disc_res.prop[i].len;
        memcpy(peer_bdname, param->disc_res.prop[i].val, peer_bdname_len);
        peer_bdname_len--; // len includes 0 terminator
        log_v("ESP_BT_GAP_DISC_RES_EVT : BDNAME :  %s : %d", peer_bdname,
              peer_bdname_len);
        DBG_PRINTF(", BDNAME: %s", peer_bdname);
        if (strlen(_remote_name) == peer_bdname_len &&
            strncmp(peer_bdname, _remote_name, peer_bdname_len) == 0) {
          log_i("ESP_BT_GAP_DISC_RES_EVT : SPP_START_DISCOVERY_BDNAME : %s",
                peer_bdname);
          _isRemoteAddressSet = true;
          memcpy(_peer_bd_addr, param->disc_res.bda, ESP_BD_ADDR_LEN);
          esp_bt_gap_cancel_discovery();
          // esp_spp_start_discovery(_peer_bd_addr);
        }
        break;

      case ESP_BT_GAP_DEV_PROP_COD:
        if (param->disc_res.prop[i].len <= sizeof(int)) {
          uint32_t cod = 0;
          memcpy(&cod, param->disc_res.prop[i].val,
                 param->disc_res.prop[i].len);
          log_d("ESP_BT_GAP_DEV_PROP_COD 0x%x", cod);
          DBG_PRINTF(", COD: 0x%x", cod);
        } else {
          log_d("ESP_BT_GAP_DEV_PROP_COD invalid COD: Value size larger than "
                "integer");
        }
        break;

      case ESP_BT_GAP_DEV_PROP_RSSI:
        if (param->disc_res.prop[i].len <= sizeof(int8_t)) {
          int8_t rssi = 0;
          memcpy(&rssi, param->disc_res.prop[i].val,
                 param->disc_res.prop[i].len);
          log_d("ESP_BT_GAP_DEV_PROP_RSSI %d", rssi);
          DBG_PRINTF(", RSSI: %d", rssi);
        } else {
          log_d("ESP_BT_GAP_DEV_PROP_RSSI invalid RSSI: Value size larger than "
                "integer");
        }
        break;

      default:
        log_i("ESP_BT_GAP_DISC_RES_EVT unknown property [%d]:type:%d", i,
              param->disc_res.prop[i].type);
        break;
      }
      if (_isRemoteAddressSet)
        break;
    }
  } break;

  case ESP_BT_GAP_DISC_STATE_CHANGED_EVT:
    if (param->disc_st_chg.state == ESP_BT_GAP_DISCOVERY_STOPPED) {
      log_i("ESP_BT_GAP_DISC_STATE_CHANGED_EVT stopped");
      // xEventGroupClearBits(_bt_event_group, BT_DISCOVERY_RUNNING);
      // xEventGroupSetBits(_bt_event_group, BT_DISCOVERY_COMPLETED);
      start_ble_scan(5);
    } else { // ESP_BT_GAP_DISCOVERY_STARTED
      log_i("ESP_BT_GAP_DISC_STATE_CHANGED_EVT started");
      // xEventGroupClearBits(_bt_event_group, BT_DISCOVERY_COMPLETED);
      // xEventGroupSetBits(_bt_event_group, BT_DISCOVERY_RUNNING);
    }
    break;

  case ESP_BT_GAP_RMT_SRVCS_EVT:
    log_i("ESP_BT_GAP_RMT_SRVCS_EVT: status = %d, num_uuids = %d",
          param->rmt_srvcs.stat, param->rmt_srvcs.num_uuids);
    break;

  case ESP_BT_GAP_RMT_SRVC_REC_EVT:
    log_i("ESP_BT_GAP_RMT_SRVC_REC_EVT: status = %d", param->rmt_srvc_rec.stat);
    break;

  case ESP_BT_GAP_AUTH_CMPL_EVT:
    if (param->auth_cmpl.stat == ESP_BT_STATUS_SUCCESS) {
      log_v("authentication success: %s", param->auth_cmpl.device_name);
      //      if (auth_complete_callback) {
      //        auth_complete_callback(true);
      //      }
    } else {
      log_e("authentication failed, status:%d", param->auth_cmpl.stat);
      //      if (auth_complete_callback) {
      //        auth_complete_callback(false);
      //      }
    }
    break;

  case ESP_BT_GAP_PIN_REQ_EVT:
    // default pairing pins
    log_i("ESP_BT_GAP_PIN_REQ_EVT min_16_digit:%d",
          param->pin_req.min_16_digit);
    if (param->pin_req.min_16_digit) {
      log_i("Input pin code: 0000 0000 0000 0000");
      esp_bt_pin_code_t pin_code;
      memset(pin_code, '0', ESP_BT_PIN_CODE_LEN);
      esp_bt_gap_pin_reply(param->pin_req.bda, true, 16, pin_code);
    } else {
      log_i("Input pin code: 1234");
      esp_bt_pin_code_t pin_code;
      memcpy(pin_code, "1234", 4);
      esp_bt_gap_pin_reply(param->pin_req.bda, true, 4, pin_code);
    }
    break;

  case ESP_BT_GAP_CFM_REQ_EVT:
    log_i("ESP_BT_GAP_CFM_REQ_EVT Please compare the numeric value: %d",
          param->cfm_req.num_val);
    //    if (confirm_request_callback) {
    //      memcpy(current_bd_addr, param->cfm_req.bda, sizeof(esp_bd_addr_t));
    //      confirm_request_callback(param->cfm_req.num_val);
    //    } else {
    //      esp_bt_gap_ssp_confirm_reply(param->cfm_req.bda, true);
    //    }
    break;

  case ESP_BT_GAP_KEY_NOTIF_EVT:
    log_i("ESP_BT_GAP_KEY_NOTIF_EVT passkey:%d", param->key_notif.passkey);
    break;

  case ESP_BT_GAP_KEY_REQ_EVT:
    log_i("ESP_BT_GAP_KEY_REQ_EVT Please enter passkey!");
    break;

  case ESP_BT_GAP_CONFIG_EIR_DATA_EVT:
    log_i("ESP_BT_GAP_CONFIG_EIR_DATA_EVT: stat:%d num:%d",
          param->config_eir_data.stat, param->config_eir_data.eir_type_num);
    break;

  case ESP_BT_GAP_READ_REMOTE_NAME_EVT:
    if (param->read_rmt_name.stat == ESP_BT_STATUS_SUCCESS) {
      log_i("ESP_BT_GAP_READ_REMOTE_NAME_EVT: %s",
            param->read_rmt_name.rmt_name);
    } else {
      log_i("ESP_BT_GAP_READ_REMOTE_NAME_EVT: no success stat:%d",
            param->read_rmt_name.stat);
    }
    break;

  case ESP_BT_GAP_MODE_CHG_EVT:
    log_i("ESP_BT_GAP_MODE_CHG_EVT: mode: %d", param->mode_chg.mode);
    break;

  default:
    log_i("ESP_BT_GAP_* unknown message: %d", event);
    break;
  }
}

#if CONFIG_BT_BLE_ENABLED
static void handle_ble_device_result(esp_ble_gap_cb_param_t *scan_result) {
  uint16_t uuid = 0;
  uint16_t appearance = 0;
  char name[64] = {0};

  uint8_t uuid_len = 0;
  uint8_t *uuid_d = esp_ble_resolve_adv_data(
      scan_result->scan_rst.ble_adv, ESP_BLE_AD_TYPE_16SRV_CMPL, &uuid_len);
  if (uuid_d != NULL && uuid_len) {
    uuid = uuid_d[0] + (uuid_d[1] << 8);
  }

  uint8_t appearance_len = 0;
  uint8_t *appearance_d =
      esp_ble_resolve_adv_data(scan_result->scan_rst.ble_adv,
                               ESP_BLE_AD_TYPE_APPEARANCE, &appearance_len);
  if (appearance_d != NULL && appearance_len) {
    appearance = appearance_d[0] + (appearance_d[1] << 8);
  }

  uint8_t adv_name_len = 0;
  uint8_t *adv_name = esp_ble_resolve_adv_data(
      scan_result->scan_rst.ble_adv, ESP_BLE_AD_TYPE_NAME_CMPL, &adv_name_len);

  if (adv_name == NULL) {
    adv_name =
        esp_ble_resolve_adv_data(scan_result->scan_rst.ble_adv,
                                 ESP_BLE_AD_TYPE_NAME_SHORT, &adv_name_len);
  }

  if (adv_name != NULL && adv_name_len) {
    memcpy(name, adv_name, adv_name_len);
    name[adv_name_len] = 0;
  }

  if (scan_result->scan_rst.rssi > -75) {
    DBG_PRINTF("\nBLE: " ESP_BD_ADDR_STR ", ",
               ESP_BD_ADDR_HEX(scan_result->scan_rst.bda));
    DBG_PRINTF("RSSI: %d, ", scan_result->scan_rst.rssi);
    DBG_PRINTF("UUID: 0x%04x, ", uuid);
    DBG_PRINTF("APPEARANCE: 0x%04x, ", appearance);
    DBG_PRINTF("ADDR_TYPE: '%s'",
               ble_addr_type_str(scan_result->scan_rst.ble_addr_type));
    if (adv_name_len) {
      DBG_PRINTF(", NAME: '%s'", name);
    }
  }
  if (uuid == ESP_GATT_UUID_HID_SVC) {
    // add_ble_scan_result(scan_rst->bda, scan_rst->ble_addr_type, appearance,
    // adv_name, adv_name_len, scan_rst->rssi);
  }
}

static esp_ble_scan_params_t hid_scan_params = {
    .scan_type = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval = 0x50,
    .scan_window = 0x30,
    .scan_duplicate = BLE_SCAN_DUPLICATE_ENABLE,
};

static esp_err_t start_ble_scan(uint32_t seconds) {
  esp_err_t ret = ESP_OK;
  if ((ret = esp_ble_gap_set_scan_params(&hid_scan_params)) != ESP_OK) {
    log_e("esp_ble_gap_set_scan_params failed: %d", ret);
    return ret;
  }

  if ((ret = esp_ble_gap_start_scanning(seconds)) != ESP_OK) {
    log_e("esp_ble_gap_start_scanning failed: %d", ret);
    return ret;
  }
  return ret;
}

const char *esp_ble_key_type_str(esp_ble_key_type_t key_type) {
  const char *key_str = NULL;
  switch (key_type) {
  case ESP_LE_KEY_NONE:
    key_str = "ESP_LE_KEY_NONE";
    break;
  case ESP_LE_KEY_PENC:
    key_str = "ESP_LE_KEY_PENC";
    break;
  case ESP_LE_KEY_PID:
    key_str = "ESP_LE_KEY_PID";
    break;
  case ESP_LE_KEY_PCSRK:
    key_str = "ESP_LE_KEY_PCSRK";
    break;
  case ESP_LE_KEY_PLK:
    key_str = "ESP_LE_KEY_PLK";
    break;
  case ESP_LE_KEY_LLK:
    key_str = "ESP_LE_KEY_LLK";
    break;
  case ESP_LE_KEY_LENC:
    key_str = "ESP_LE_KEY_LENC";
    break;
  case ESP_LE_KEY_LID:
    key_str = "ESP_LE_KEY_LID";
    break;
  case ESP_LE_KEY_LCSRK:
    key_str = "ESP_LE_KEY_LCSRK";
    break;
  default:
    key_str = "INVALID BLE KEY TYPE";
    break;
  }
  return key_str;
}

const char *ble_gap_evt_str(uint8_t event) {
  static const char *ble_gap_evt_names[] = {"ADV_DATA_SET_COMPLETE",
                                            "SCAN_RSP_DATA_SET_COMPLETE",
                                            "SCAN_PARAM_SET_COMPLETE",
                                            "SCAN_RESULT",
                                            "ADV_DATA_RAW_SET_COMPLETE",
                                            "SCAN_RSP_DATA_RAW_SET_COMPLETE",
                                            "ADV_START_COMPLETE",
                                            "SCAN_START_COMPLETE",
                                            "AUTH_CMPL",
                                            "KEY",
                                            "SEC_REQ",
                                            "PASSKEY_NOTIF",
                                            "PASSKEY_REQ",
                                            "OOB_REQ",
                                            "LOCAL_IR",
                                            "LOCAL_ER",
                                            "NC_REQ",
                                            "ADV_STOP_COMPLETE",
                                            "SCAN_STOP_COMPLETE",
                                            "SET_STATIC_RAND_ADDR",
                                            "UPDATE_CONN_PARAMS",
                                            "SET_PKT_LENGTH_COMPLETE",
                                            "SET_LOCAL_PRIVACY_COMPLETE",
                                            "REMOVE_BOND_DEV_COMPLETE",
                                            "CLEAR_BOND_DEV_COMPLETE",
                                            "GET_BOND_DEV_COMPLETE",
                                            "READ_RSSI_COMPLETE",
                                            "UPDATE_WHITELIST_COMPLETE"};
  if (event >= SIZEOF_ARRAY(ble_gap_evt_names)) {
    return "UNKNOWN";
  }
  return ble_gap_evt_names[event];
}

const char *ble_addr_type_str(esp_ble_addr_type_t ble_addr_type) {
  static const char *ble_addr_type_names[] = {"PUBLIC", "RANDOM", "RPA_PUBLIC",
                                              "RPA_RANDOM"};
  if (ble_addr_type > BLE_ADDR_TYPE_RPA_RANDOM) {
    return "UNKNOWN";
  }
  return ble_addr_type_names[ble_addr_type];
}

/*
 * BLE GAP
 * */

static void esp_ble_gap_cb(esp_gap_ble_cb_event_t event,
                           esp_ble_gap_cb_param_t *param) {
  switch (event) {
  /*
   * SCAN
   * */
  case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT: {
    log_i("BLE GAP EVENT SCAN_PARAM_SET_COMPLETE");
    break;
  }
  case ESP_GAP_BLE_SCAN_RESULT_EVT: {
    esp_ble_gap_cb_param_t *scan_result = (esp_ble_gap_cb_param_t *)param;
    switch (scan_result->scan_rst.search_evt) {
    case ESP_GAP_SEARCH_INQ_RES_EVT: {
      handle_ble_device_result(scan_result);
      break;
    }
    case ESP_GAP_SEARCH_INQ_CMPL_EVT:
      log_i("BLE GAP EVENT SCAN DONE: %d", scan_result->scan_rst.num_resps);
      start_bt_scan(5);
      break;
    default:
      break;
    }
    break;
  }
  case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT: {
    log_i("BLE GAP EVENT SCAN CANCELED");
    start_bt_scan(5);
    break;
  }

  /*
   * ADVERTISEMENT
   * */
  case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
    log_i("BLE GAP ADV_DATA_SET_COMPLETE");
    break;

  case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
    log_i("BLE GAP ADV_START_COMPLETE");
    break;

  /*
   * AUTHENTICATION
   * */
  case ESP_GAP_BLE_AUTH_CMPL_EVT:
    if (!param->ble_security.auth_cmpl.success) {
      log_e("BLE GAP AUTH ERROR: 0x%x",
            param->ble_security.auth_cmpl.fail_reason);
    } else {
      log_i("BLE GAP AUTH SUCCESS");
    }
    break;

  case ESP_GAP_BLE_KEY_EVT: // shows the ble key info share with peer device to
                            // the user.
    log_i("BLE GAP KEY type = %s",
          esp_ble_key_type_str(param->ble_security.ble_key.key_type));
    break;

  case ESP_GAP_BLE_PASSKEY_NOTIF_EVT: // ESP_IO_CAP_OUT
    // The app will receive this evt when the IO has Output capability and the
    // peer device IO has Input capability. Show the passkey number to the user
    // to input it in the peer device.
    log_i("BLE GAP PASSKEY_NOTIF passkey:%" PRIu32,
          param->ble_security.key_notif.passkey);
    break;

  case ESP_GAP_BLE_NC_REQ_EVT: // ESP_IO_CAP_IO
    // The app will receive this event when the IO has DisplayYesNO capability
    // and the peer device IO also has DisplayYesNo capability. show the passkey
    // number to the user to confirm it with the number displayed by peer
    // device.
    log_i("BLE GAP NC_REQ passkey:%" PRIu32,
          param->ble_security.key_notif.passkey);
    esp_ble_confirm_reply(param->ble_security.key_notif.bd_addr, true);
    break;

  case ESP_GAP_BLE_PASSKEY_REQ_EVT: // ESP_IO_CAP_IN
    // The app will receive this evt when the IO has Input capability and the
    // peer device IO has Output capability. See the passkey number on the peer
    // device and send it back.
    log_i("BLE GAP PASSKEY_REQ");
    // esp_ble_passkey_reply(param->ble_security.ble_req.bd_addr, true, 1234);
    break;

  case ESP_GAP_BLE_SEC_REQ_EVT:
    log_i("BLE GAP SEC_REQ");
    // Send the positive(true) security response to the peer device to accept
    // the security request. If not accept the security request, should send the
    // security response with negative(false) accept value.
    esp_ble_gap_security_rsp(param->ble_security.ble_req.bd_addr, true);
    break;

  default:
    log_i("BLE GAP EVENT %s", ble_gap_evt_str(event));
    break;
  }
}
#endif /* CONFIG_BT_BLE_ENABLED */

static bool _init_bt(const char *deviceName) {
  esp_err_t ret;

  log_i("_init_bt");
  if (!btStarted() && !btStart()) {
    log_e("initialize controller failed");
    return false;
  }

  esp_bluedroid_status_t bt_state = esp_bluedroid_get_status();
  if (bt_state == ESP_BLUEDROID_STATUS_UNINITIALIZED) {
    if (esp_bluedroid_init()) {
      log_e("initialize bluedroid failed");
      return false;
    }
  }

  if (bt_state != ESP_BLUEDROID_STATUS_ENABLED) {
    if (esp_bluedroid_enable()) {
      log_e("enable bluedroid failed");
      return false;
    }
  }

  log_i("device name set");
  esp_bt_dev_set_device_name(deviceName);

  if (esp_bt_gap_register_callback(esp_bt_gap_cb) != ESP_OK) {
    log_e("gap register failed");
    return false;
  }

  // Init BT Classic
  //
#if (CONFIG_BT_SSP_ENABLED)
  /* Set default parameters for Secure Simple Pairing */
  log_i("Simple Secure Pairing");
  esp_bt_sp_param_t param_type = ESP_BT_SP_IOCAP_MODE;
  esp_bt_io_cap_t iocap = ESP_BT_IO_CAP_IO;
  esp_bt_gap_set_security_param(param_type, &iocap, sizeof(uint8_t));
#endif

  // the default BTA_DM_COD_LOUDSPEAKER does not work with the macOS BT stack
  esp_bt_cod_t cod;
  uint32_t Pixel4a = 0x5a020c;
  cod.major = (Pixel4a >> 8) & 0b11111;
  cod.minor = (Pixel4a >> 2) & 0b111111;
  cod.service = (Pixel4a >> 13) & 0b11111111111;
  log_i("cod = %lx", *(uint32_t *)&cod);
  if (esp_bt_gap_set_cod(cod, ESP_BT_INIT_COD) != ESP_OK) {
    log_e("set cod failed");
    return false;
  }

  // Allow BT devices to connect back to us
  if ((ret = esp_bt_gap_set_scan_mode(ESP_BT_CONNECTABLE,
                                      ESP_BT_NON_DISCOVERABLE)) != ESP_OK) {
    log_e("esp_bt_gap_set_scan_mode failed: %d", ret);
    return false;
  }

  // Init BLE
  //
  if ((ret = esp_ble_gap_register_callback(esp_ble_gap_cb)) != ESP_OK) {
    log_e("esp_ble_gap_register_callback failed: %d", ret);
    return false;
  }
  return true;
}

static bool _stop_bt() {
  log_i("_stop_bt");
  if (btStarted()) {
    esp_bluedroid_disable();
    esp_bluedroid_deinit();
    btStop();
  }
  return true;
}

void printDeviceAddress() {
  const uint8_t *point = esp_bt_dev_get_address();

  for (int i = 0; i < 6; i++) {
    char str[3];

    snprintf(str, sizeof(str), "%02X", (int)point[i]);
    Serial.print(str);
    if (i < 5) {
      Serial.print(":");
    }
  }
}

void setup() {
  Serial.begin(115200);
  _init_bt("ESP32 BT Dual Mode");
  printDeviceAddress();
  start_bt_scan(5);
}

void loop() {}
