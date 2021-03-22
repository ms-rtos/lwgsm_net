/* Hostname event function, called when lwgsm_sms_send() function finishes */
void
sms_send_fn(lwgsmr_t res, void* arg) {
    /* Check actual result from device */
    if (res == lwgsmOK) {
        printf("SMS sent successfully\r\n");
    } else {
        printf("Error trying to send SMS\r\n");
    }
}

/* Somewhere in thread and/or other GSM event function */

/* Send SMS in non-blocking mode */
/* Function now returns if command has been sent to internal message queue */
if (lwgsm_sms_send("number", "text message", sms_send_fn, NULL, 0 /* 0 means non-blocking call */) == lwgsmOK) {
    /* At this point we only know that command has been sent to queue */
    printf("SMS send message command sent to queue.\r\n");
} else {
    /* Error writing message to queue */
    printf("Cannot send SMS send message command to queue. Maybe out of memory? Check result from function\r\n");
}