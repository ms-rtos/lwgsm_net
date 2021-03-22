/*
 * SMS send and receive thread.
 *
 * Waits for received SMS and then replies with
 */
#include "sms_send_receive_thread.h"
#include "lwgsm/lwgsm.h"
#include "lwgsm/lwgsm_mem.h"

#if !LWGSM_CFG_SMS
#error "SMS must be enabled to run this example"
#endif /* !LWGSM_CFG_SMS */

static lwgsmr_t sms_evt_func(lwgsm_evt_t* evt);

/**
 * \brief           SMS entry information
 */
typedef struct {
    lwgsm_mem_t mem;
    size_t pos;
} sms_receive_t;

/**
 * \brief           SMS message box
 */
static lwgsm_sys_mbox_t
sms_mbox;

/**
 * \brief           SMS read entry
 */
static lwgsm_sms_entry_t
sms_entry;

/**
 * \brief           SMS Receive Send thread function
 */
void
sms_send_receive_thread(void const* arg) {
    sms_receive_t* sms;

    /* Create message box */
    if (!lwgsm_sys_mbox_create(&sms_mbox, 5)) {
        goto terminate;
    }

    /* Register callback function for SMS */
    if (lwgsm_evt_register(sms_evt_func) != lwgsmOK) {
        goto terminate;
    }

    /* First enable SMS functionality */
    if (lwgsm_sms_enable(NULL, NULL, 1) == lwgsmOK) {
        printf("SMS enabled. Send new SMS from your phone to device.\r\n");
    } else {
        printf("Cannot enable SMS functionality!\r\n");
        while (1) {
            lwgsm_delay(1000);
        }
    }

    /* User can start now */
    printf("Start by sending first SMS to device...\r\n");

    while (1) {
        /* Get SMS entry from message queue */
        while (lwgsm_sys_mbox_get(&sms_mbox, (void**)&sms, 0) == LWGSM_SYS_TIMEOUT || sms == NULL) {}

        /* We have new SMS now */
        printf("New SMS received!\r\n");

        /* Read SMS from device */
        if (lwgsm_sms_read(sms->mem, sms->pos, &sms_entry, 1, NULL, NULL, 1) == lwgsmOK) {
            printf("SMS read ok. Number: %s, content: %s\r\n", sms_entry.number, sms_entry.data);

            /* Send reply back */
            if (lwgsm_sms_send(sms_entry.number, sms_entry.data, NULL, NULL, 1) == lwgsmOK) {
                printf("SMS sent back successfully!\r\n");
            } else {
                printf("Cannot send SMS back!\r\n");
            }

            /* Delete SMS from device memory */
            if (lwgsm_sms_delete(sms->mem, sms->pos, NULL, NULL, 1) == lwgsmOK) {
                printf("Received SMS deleted!\r\n");
            } else {
                printf("Cannot delete received SMS!\r\n");
            }
        } else {
            printf("Cannot read SMS!\r\n");
        }

        /* Now free the memory */
        lwgsm_mem_free_s((void**)&sms);
    }

terminate:
    if (lwgsm_sys_mbox_isvalid(&sms_mbox)) {
        /* Lock to make sure GSM stack won't process any callbacks while we are cleaning */
        lwgsm_core_lock();

        /* Clean mbox first */
        while (lwgsm_sys_mbox_getnow(&sms_mbox, (void**)&sms)) {
            lwgsm_mem_free_s((void**)&sms);
        }

        /* Delete mbox */
        lwgsm_sys_mbox_delete(&sms_mbox);
        lwgsm_sys_mbox_invalid(&sms_mbox);

        lwgsm_core_unlock();

        /* Now mbox is not valid anymore and event won't write any data */
    }
}

/**
 * \brief           Event function for received SMS
 * \param[in]       evt: GSM event
 * \return          \ref lwgsmOK on success, member of \ref lwgsmr_t otherwise
 */
static lwgsmr_t
sms_evt_func(lwgsm_evt_t* evt) {
    switch (lwgsm_evt_get_type(evt)) {
        case LWGSM_EVT_SMS_RECV: {                /* New SMS received indicator */
            uint8_t success = 0;
            sms_receive_t* sms_rx = lwgsm_mem_malloc(sizeof(*sms_rx));
            if (sms_rx != NULL) {
                sms_rx->mem = lwgsm_evt_sms_recv_get_mem(evt);
                sms_rx->pos = lwgsm_evt_sms_recv_get_pos(evt);

                /* Write to receive queue */
                if (!lwgsm_sys_mbox_isvalid(&sms_mbox) || !lwgsm_sys_mbox_putnow(&sms_mbox, sms_rx)) {
                    lwgsm_mem_free_s((void**)&sms_rx);
                } else {
                    success = 1;
                }
            }

            /* Force SMS delete if not written successfully */
            if (!success) {
                lwgsm_sms_delete(lwgsm_evt_sms_recv_get_mem(evt), lwgsm_evt_sms_recv_get_pos(evt), NULL, NULL, 0);
            }
            break;
        }
        default:
            break;
    }

    return lwgsmOK;
}
